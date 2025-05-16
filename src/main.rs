use std::{ffi::c_void, io::{self, Write}, mem, ptr::null_mut, str, sync::Arc};

use windows::{
    core::*,
    Win32::{Foundation::*, Security::SECURITY_ATTRIBUTES, Storage::FileSystem::*, System::{Console::*, Pipes::*, Threading::*, Memory::HeapFree}}, // for ReadFile/WriteFile
};

use windows::Win32::System::Memory::{HeapAlloc, GetProcessHeap};
#[derive(Clone)]
struct PtyPair { 
    master: Master,
    slave: Slave
}
#[derive(Clone)]
struct Master {
    read: HANDLE,
    write: HANDLE
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
        let (pair, master_for_thread) = Self::create_pseudo_console().unwrap();        
        let master = pair.master.clone();
        let slave =  pair.slave.clone();
        Self::start_read_thread(master_for_thread);
        PtyPair { master, slave }
    }

    fn write(self: &Self, data: &str) {
        Self::master_stdin(&self.master, data);
    }
    // Everytime it is ran (in the future) I need to return JSONValue (from serde)
    fn start_read_thread(master: Master) {
        let master = Arc::new(master);
        std::thread::spawn(move || {
            let buf_size = 1024;
            let mut buffer = vec![0u8; buf_size];
            loop {
                
                let mut bytes_read = 0;

                println!("Bytes read from master stdout: {}", bytes_read);  
                let success_read = unsafe {
                    ReadFile(
                        master.read,    
                        Some(&mut buffer[..]),
                        Some(&mut bytes_read),
                        None,
                    )
                };

                
                println!("Bytes read from master stdout: {}", bytes_read);
                match success_read {
                    Ok(_) => {
                        if bytes_read == 0 {
                            println!("Child process closed the output.");
                            break;
                        }
                        let output = String::from_utf8_lossy(&buffer[..bytes_read as usize]);
                        print!("{}", output);
                        use std::io::Write;
                        std::io::stdout().flush().unwrap();
                    }
                    Err(e) => {
                        println!("Failed to read master stdout: {:?}", e);
                        break;
                    }
                }
            }
        });
    }

    fn master_stdin(master: &Master, data: &str) {
        let mut bytes_written: u32 = 0;

        let mut cmd = data.to_string();
        if !cmd.ends_with("\r\n") {
            cmd.push_str("\r\n");
        }
        let bytes = cmd.as_bytes();

        let success = unsafe {
            WriteFile(
                master.write,
                Some(bytes),            
                Some(&mut bytes_written),
                None,           
            )
        };  


        match success {
            Ok(_) => {
                println!("data correctly written: {:?}", str::from_utf8(bytes).unwrap());
            }
            Err(e) => {
                println!("Failed to write to stdin: {:?}", e);
            }
        }

    }

    fn create_pseudo_console() ->  io::Result<(PtyPair, Master)> {

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

        println!("stdin_read: {:?}", stdin_read);
        println!("stdin_write: {:?}", stdin_write);
        println!("stdout_read: {:?}", stdout_read);
        println!("stdout_write: {:?}", stdout_write);

        match handle_one {
            Ok(_) => println!("handle one created successfully."),
            Err(e) => {
                println!("Failed to create handle : {:?}", e);
                // You can get the error code too
                println!("HRESULT: {:?}", e.code());
            }
        }

        match handle_two {
            Ok(_) => println!("handle two created successfully."),
            Err(e) => {
                println!("Failed to create handle : {:?}", e);
                // You can get the error code too
                println!("HRESULT: {:?}", e.code());
            }
        }

        let r1 =   unsafe { SetHandleInformation(stdin_write, 0x00000001,  HANDLE_FLAGS(0)) };
        let r2 =   unsafe { SetHandleInformation(stdout_read, 0x00000001,  HANDLE_FLAGS(0)) };

        match r1 {
            Ok(_) => println!("Handle informations set successfully."),
            Err(e) => {
                println!("Failed to set Handle informations: {:?}", e);
                println!("HRESULT: {:?}", e.code());
            }
        }

        match r2 {
            Ok(_) => println!("Handle informations set successfully."),
            Err(e) => {
                println!("Failed to set Handle informations: {:?}", e);
                println!("HRESULT: {:?}", e.code());
            }
        }

        // we are not spawning a console but it is still needed 
        let size = COORD { X: 80, Y: 80 };
        let hpc: HPCON = unsafe { CreatePseudoConsole(size, stdin_read, stdout_write, 0)? };

        let mut attr_list_size = 0;

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

        let attr_list_mem: LPPROC_THREAD_ATTRIBUTE_LIST = unsafe {
            mem::transmute(ptr)
        };

        let init_proc =    unsafe {
            InitializeProcThreadAttributeList(  
                Some(attr_list_mem),
                1,
                Some(0),
                &mut attr_list_size as *mut usize,
            )
        };

        match init_proc {
            Ok(_) => println!("Attribute list initialized successfully."),
            Err(e) => {
                println!("Failed to initialize attribute list: {:?}", e);
                // You can get the error code too
                println!("HRESULT: {:?}", e.code());
            }
        }

        let update_proc_attr = unsafe { UpdateProcThreadAttribute(
            attr_list_mem,
            0,
            PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE as usize,
            Some(&hpc as *const _ as *mut _),
            size_of::<HPCON>(),
            None,
            None,
        ) };

        match update_proc_attr {
            Ok(_) => println!("Update proc attribute."),
            Err(e) => {
                println!("Failed to initialize attribute list: {:?}", e);
                println!("HRESULT: {:?}", e.code());
            }
        }

        let mut cmdline: Vec<u16> = "cmd.exe\0".encode_utf16().chain(Some(0)).collect();

        let mut si_ex = STARTUPINFOEXW::default();        
        let mut process_info = PROCESS_INFORMATION::default();

        si_ex.StartupInfo.cb = size_of::<STARTUPINFOEXW>() as u32;
        si_ex.lpAttributeList = attr_list_mem;

        let success = unsafe {
            CreateProcessW(
                PCWSTR::null(),
                 Some(PWSTR(cmdline.as_mut_ptr())),
                None,
                None,
                true.into(),
                EXTENDED_STARTUPINFO_PRESENT | CREATE_UNICODE_ENVIRONMENT,
                None,
                None,
                &si_ex.StartupInfo as *const _,
                &mut process_info,
            )
        };

        unsafe {
            let _ = CloseHandle(stdin_read);
            let _ = CloseHandle(stdout_write);
            let _ = CloseHandle(process_info.hThread);
        }

         match success {
            Ok(_) => {
                println!("Process created successfully.");
                println!("Process handle: {:?}", process_info.hProcess);
                println!("Process ID: {}", process_info.dwProcessId);
            }
            Err(e) => {
                println!("Failed to create process: {:?}", e);
                println!("HRESULT: {:?}", e.code());
            }
        }

       let pair = PtyPair {
                master: { Master { read: stdout_read, write: stdin_write }}, 
                slave: Slave { read: stdin_read, write: stdout_write } 
        };

        let read_handle_for_thread = Self::duplicate_handle(stdout_read)?;
        let write_handle_for_thread = Self::duplicate_handle(stdin_write)?;

        let master_for_thread = Master {
            read: read_handle_for_thread,
            write: write_handle_for_thread,
        };
        unsafe {
            DeleteProcThreadAttributeList(attr_list_mem);
            let _ = HeapFree(GetProcessHeap().unwrap(), windows::Win32::System::Memory::HEAP_FLAGS(0), Some(attr_list_mem.0 as *const c_void));
        }

        return     Ok((pair, master_for_thread))
    }


    fn duplicate_handle(handle: HANDLE) -> windows::core::Result<HANDLE> {
        let mut dup_handle = HANDLE::default();

        unsafe {
            let success = DuplicateHandle(
                GetCurrentProcess(),
                handle,
                GetCurrentProcess(),
                &mut dup_handle,
                0,
                false,
                DUPLICATE_SAME_ACCESS,
            );

        if let Err(v) = success {
                Err(windows::core::Error::from_win32())
            } else {
                Ok(dup_handle)
        }
        }
    }
}

fn main() {
    let stdin = io::stdin();
    let mut input = String::new();
    let pair = PtyPair::new();

    // Wait a bit for process to start and output initial text
    std::thread::sleep(std::time::Duration::from_millis(500));


    loop {
        print!("Robo > ");
        
        io::stdout().flush().unwrap(); // Make sure the prompt appears

        input.clear();

        match stdin.read_line(&mut input) {
            Ok(n) => {
                pair.write(&input);
            }
            Err(error) => println!("error: {error}"),
        }

        if input.trim() == "exit" {
            break;
        }
                

    }
}
