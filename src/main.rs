use std::{ffi::c_void, io::{self, Write}, ptr::null_mut, str, sync::{Arc, Mutex}, thread};
use simple_logger::SimpleLogger;
use log::{info, warn, error, debug, trace};

use windows::{
    core::*,
    Win32::{Foundation::*, Security::SECURITY_ATTRIBUTES, Storage::FileSystem::*, System::{Console::*, Pipes::*, Threading::*, Memory::HeapFree}}, // for ReadFile/WriteFile
};

use windows::Win32::System::Memory::{HeapAlloc, GetProcessHeap};

#[derive(Clone)]
struct PtyPair { 
    master: Master,
    slave: Slave,
    hpc: HPCON,
    process_info: PROCESS_INFORMATION
}
#[derive(Clone)]
struct Master {
    read: Arc<Mutex<HANDLE>>,
    write: Arc<Mutex<HANDLE>>,
}
#[derive(Clone)]
struct Slave {
    read: HANDLE,
    write: HANDLE,
}

// we gotta do this, so it is safe between threads (apparently)
unsafe impl Send for Master {}
unsafe impl Sync for Master {}
// impl Drop for PtyPair {
//     fn drop(&mut self) {
//         unsafe {
//             ClosePseudoConsole(self.hpc);
//             CloseHandle(self.process_info.hProcess);
//             CloseHandle(self.process_info.hThread);
//             // Close all pipe handles
//             if !self.master.read.0.is_null() {
//                 CloseHandle(self.master.read);
//             }
//             if !self.master.write.0.is_null() {
//                 CloseHandle(self.master.write);
//             }
//             if !self.slave.read.0.is_null() {
//                 CloseHandle(self.slave.read);
//             }
//             if !self.slave.write.0.is_null() {
//                 CloseHandle(self.slave.write);
//             }
//         }
//     }
// }

impl PtyPair {
    fn new() -> Self {

        SimpleLogger::new().without_timestamps().init().unwrap();

        let pair = Self::create_pseudo_console().unwrap();        
        let master = pair.master.clone();
        let slave =  pair.slave.clone();



        let stdin = io::stdin();
        let mut input = String::new();
        
        loop {
            
            input.clear();
            
            print!("Robo > ");
            io::stdout().flush().unwrap();

            stdin.read_line(&mut input).unwrap();
            if input.trim() == "exit" {
                break;
            }

            pair.write(&input);
        }

        unsafe {
            WaitForSingleObject(pair.process_info.hProcess, INFINITE);
            let mut exit_code = 0;
            let _ = GetExitCodeProcess(pair.process_info.hProcess, &mut exit_code);
            debug!("Process exit code: {}", exit_code);
        }


            PtyPair { master, slave, hpc: pair.hpc, process_info: pair.process_info }
        }


    fn read_master_stdout(master: Master){
        
        let buf_size = 1024;
        let mut buffer = vec![0u8; buf_size];
        loop {
           // println!("Reading from master stdout...");
            let mut bytes_read = 0;

            // Check if the handle is valid
            if master.read.lock().unwrap().0.is_null() {
                error!("master stdout handle is null!");
                break;
            }

            debug!("Attempting to read from stdout...");

            let success_read = unsafe {
                ReadFile(
                    master.read.lock().unwrap().clone(),
                    Some(&mut buffer[..]),
                    Some(&mut bytes_read),
                    None,
                )
            };
            debug!("ReadFile result: {:?}, bytes_read: {}", success_read, bytes_read);

            match success_read {
                Ok(_) => {
                    info!("ReadFile succeeded, bytes_read: {}", bytes_read);
                    if bytes_read == 0 {
                        thread::sleep(std::time::Duration::from_millis(100));
                        continue;
                    }
                    let output = String::from_utf8_lossy(&buffer[..bytes_read as usize]);
                    info!("{}", output);
                    std::io::stdout().flush().unwrap();
                }
                Err(e) => {
                    error!("Failed to read master stdout: {:?}", e);
                    break;
                }
            }


            }
    }

    // Everytime it is ran (in the future) I need to return JSONValue (from serde)
    fn write(self: &Self, data: &str) {
        Self::master_stdin(&self.master, data);
    }

    fn master_stdin(master: &Master, data: &str) {
        let mut bytes_written: u32 = 0;

        let mut cmd = data.to_string();
        if !cmd.ends_with("\r\n") {
            cmd.push_str("\r\n");
        }
        let bytes = cmd.as_bytes();

        if master.write.lock().unwrap().0.is_null() {
            error!("stdin_write handle is null!");
            return;
        }

        let success = unsafe {
            WriteFile(
                master.write.lock().unwrap().clone(),
                Some(bytes),            
                Some(&mut bytes_written),
                None,           
            )
        };  
        
        match success {
            Ok(_) => {
                info!("data correctly written: {:?} bytes written: {}", str::from_utf8(bytes).unwrap(), bytes_written);

                //Self::read_master_stdout(master.clone());
            }
            Err(e) => {
                error!("Failed to write to stdin: {:?}", e);
            }
        }

    }

    fn create_pseudo_console() ->  io::Result<PtyPair> {

        // maybe make whole function body unsafe so I dont have to declare it more than once
        let mut stdin_read = HANDLE(null_mut());
        let mut stdin_write = HANDLE(null_mut());
        let mut stdout_read = HANDLE(null_mut());
        let mut stdout_write = HANDLE(null_mut());

        let sa = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>()  as u32,
            lpSecurityDescriptor: null_mut(),
            bInheritHandle: TRUE 
        };

        let handle_one = unsafe { CreatePipe(&mut stdin_read, &mut stdin_write, Some(&sa), 0) };
        let handle_two = unsafe { CreatePipe(&mut stdout_read, &mut stdout_write, Some(&sa), 0) };

        info!("stdin_read: {:?}", stdin_read);
        info!("stdin_write: {:?}", stdin_write);
        info!("stdout_read: {:?}", stdout_read);
        info!("stdout_write: {:?}", stdout_write);

        unsafe {
            let _ = SetHandleInformation(stdin_write, HANDLE_FLAG_INHERIT.0, HANDLE_FLAGS(0));
            let _ = SetHandleInformation(stdout_read, HANDLE_FLAG_INHERIT.0, HANDLE_FLAGS(0));
        }

        match handle_one {
            Ok(_) => info!("handle one created successfully."),
            Err(e) => {
                error!("Failed to create handle : {:?}", e);
                // You can get the error code too
                error!("HRESULT: {:?}", e.code());
            }
        }

        match handle_two {
            Ok(_) => info!("handle two created successfully."),
            Err(e) => {
                error!("Failed to create handle : {:?}", e);
                // You can get the error code too
                error!("HRESULT: {:?}", e.code());
            }
        }
        // we are not spawning a console but it is still needed  (the size)
        const DEFAULT_CONSOLE_SIZE: COORD = COORD { X: 80, Y: 80 }; 
        let hpc: HPCON = unsafe { CreatePseudoConsole(DEFAULT_CONSOLE_SIZE, stdin_read, stdout_write, 0)? };

        let mut attr_list_size = 0;

        if hpc.is_invalid() {
            return Err(io::Error::new(io::ErrorKind::Other, "Failed to create pseudoconsole"));
        }

        // we have to do this twice, to find out the size we need (apparently)

        // also THIS IS BOUND TO fail (apparently also)
        let _ =  unsafe { InitializeProcThreadAttributeList(
                    None,          
                    1,
                    None,             
                    &mut attr_list_size as *mut usize,
                )
        };

        let ptr = unsafe { HeapAlloc(GetProcessHeap().unwrap(), windows::Win32::System::Memory::HEAP_FLAGS(0), attr_list_size) };

        let attr_list_mem: LPPROC_THREAD_ATTRIBUTE_LIST = windows::Win32::System::Threading::LPPROC_THREAD_ATTRIBUTE_LIST(ptr.cast());
        
        let init_proc =    unsafe {
            InitializeProcThreadAttributeList(  
                Some(attr_list_mem),
                1,
                Some(0),
                &mut attr_list_size as *mut usize,
            )
        };

        match init_proc {
            Ok(_) => info!("Attribute list initialized successfully."),
            Err(e) => {
                error!("Failed to initialize attribute list: {:?}", e);
                // You can get the error code too
                error!("HRESULT: {:?}", e.code());
            }
        }

        let update_proc_attr = unsafe { UpdateProcThreadAttribute(
            attr_list_mem,
            0,
            PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE as usize,
            Some(&hpc.0  as *const _ as *const c_void),
            size_of::<HPCON>(),
            None,
            None,
        ) };

        match update_proc_attr {
            Ok(_) => info!("Update proc attribute."),
            Err(e) => {
                error!("Failed to initialize attribute list: {:?}", e);
                error!("HRESULT: {:?}", e.code());
            }
        }


        let master = Master { read: Arc::new(Mutex::new(stdout_read)), write: Arc::new(Mutex::new(stdin_write)) };
        let slave = Slave { read: stdin_read, write: stdout_write };

        let process_info  = Self::start_process(master.clone(), attr_list_mem);

        let pair = PtyPair { master: master.clone(), slave: slave.clone(), hpc, process_info };
        Ok(pair)

    }

    fn start_process(master: Master, list: LPPROC_THREAD_ATTRIBUTE_LIST) -> PROCESS_INFORMATION {
        let mut cmdline: Vec<u16> = "cmd.exe\0".encode_utf16().collect();

        let mut si_ex = STARTUPINFOEXW::default();        
        let mut process_info: PROCESS_INFORMATION = PROCESS_INFORMATION::default();

        si_ex.StartupInfo.cb = size_of::<STARTUPINFOEXW>() as u32;
        si_ex.lpAttributeList = list;


        let master_for_thread = master.clone();

        thread::spawn(move || {
             let result = std::panic::catch_unwind(|| {
                Self::read_master_stdout(master_for_thread);
            });
            if let Err(e) = result {
                println!("read_master_stdout panicked: {:?}", e);
            }
        });

        let success = unsafe {
            CreateProcessW(
                PCWSTR::null(),
                 Some(PWSTR(cmdline.as_mut_ptr())),
                None,
                None,
                TRUE.as_bool(),
                EXTENDED_STARTUPINFO_PRESENT,
                None,
                None,
                &si_ex.StartupInfo as *const _,
                &mut process_info,
            )
        };

        match success {
            Ok(_) => info!("Process created successfully."),
            Err(e) => {
                error!("Failed to create process: {:?}", e);
                // You can get the error code too
                error!("HRESULT: {:?}", e.code());
            }
        }
        
        unsafe {
            DeleteProcThreadAttributeList(list);
            let _ = HeapFree(GetProcessHeap().unwrap(), windows::Win32::System::Memory::HEAP_FLAGS(0), Some(list.0 as *const c_void));
        }


        return process_info


    }

    fn check_handle_flags(handle: HANDLE) {
        let mut flags = 0;
        let result = unsafe { GetHandleInformation(handle, &mut flags) };
        if result.is_ok() {
            info!("Handle flags: {:?}", flags);
        } else {
            error!("Failed to get handle information: {:?}", result);
        }
    }

}

fn main() {
     PtyPair::new();
}
