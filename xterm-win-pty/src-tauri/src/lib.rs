// Learn more about Tauri commands at https://tauri.app/develop/calling-rust/

use std::{env, ffi::{c_void, CString}, io::{self, Write}, ptr::null_mut, str, sync::{Arc, Mutex}, thread};
use simple_logger::SimpleLogger;
use log::{info, error, debug};
use log::LevelFilter::Off;
use windows::{
    core::*,
    Win32::{Foundation::*, Security::SECURITY_ATTRIBUTES, Storage::FileSystem::*, System::{Console::*, Memory::{HeapFree, HEAP_ZERO_MEMORY}, Pipes::*, Threading::{self, *}}}, // for ReadFile/WriteFile
};

use windows::Win32::System::Memory::{HeapAlloc, GetProcessHeap};
use windows::Win32::System::JobObjects::*;


use sysinfo::{System};
use std::collections::HashSet;

#[derive(Clone)]
struct PtyPair { 
    master: Master,
    slave: Slave,
    hpc: HPCON,
    process_info: PROCESS_INFORMATION,
    h_job: HANDLE,
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

unsafe impl Send for PtyPair {}
unsafe impl Sync for PtyPair {}

// TODO: FIX DROP IMPLEMENTATION.

// impl Drop for PtyPair {
//     fn drop(&mut self) {
//         unsafe {
//             ClosePseudoConsole(self.hpc);
//             let _ = CloseHandle(self.process_info.hProcess);
//             let _ = CloseHandle(self.process_info.hThread);
//             // Close all pipe handles
//             if !self.master.read.lock().unwrap().0.is_null() {
//                 let _ = CloseHandle(self.master.read.lock().unwrap().clone());
//             }
//             if !self.master.write.lock().unwrap().0.is_null() {
//                 let _ = CloseHandle(self.master.write.lock().unwrap().clone());
//             }
//             if !self.slave.read.0.is_null() {
//                 let _ = CloseHandle(self.slave.read);
//             }
//             if !self.slave.write.0.is_null() {
//                 let _ = CloseHandle(self.slave.write);
//             }
//         }
//     }
// }


impl PtyPair {
    fn new() -> Self {

        let log = true;
        if log {
            SimpleLogger::new().with_level(Off).init().unwrap();
        } else {
            SimpleLogger::new().init().unwrap();
        }

        let pair = Self::create_pseudo_console().unwrap();
        let master = pair.master.clone();
        let slave =  pair.slave.clone();

        PtyPair { master, slave, hpc: pair.hpc, process_info: pair.process_info, h_job: pair.h_job }
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
                    println!("{}", output);
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
        Self::master_stdin(self, &self.master, data, self.process_info.dwProcessId);
    }

    fn master_stdin(self: &Self, master: &Master, data: &str, child_pid: u32) {
        let mut bytes_written: u32 = 0;


        debug!("Writing to master stdin: {:?}", data);

        let mut cmd = data.to_string();


        if !cmd.ends_with("\r\n") {
            cmd.push_str("\r\n");
        }

        // please leave it as IT IS, or change it but be ware, changes are supossed to be reflected on your Front.
        if cmd.starts_with("^C") {
            let subprocess_pid = Self::get_subprocess_pid(self);
            if subprocess_pid == 0 {
                error!("Failed to find subprocess in job");
                return;
            }

            let process_handle = unsafe {
                OpenProcess(PROCESS_TERMINATE | PROCESS_QUERY_INFORMATION, false, subprocess_pid)
            };

            if let Ok(handle) = process_handle {
                let terminate = unsafe { TerminateProcess(handle, 0) };

                if let Err(e) = terminate {
                    error!("Failed to terminate process: {:?}", e);
                    return;
                }

                return;
            } else {
                error!("Failed to open process");
                return;
            }

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
                // we can return a serde value from there
                debug!("data correctly written: {:?} bytes written: {}", str::from_utf8(bytes).unwrap(), bytes_written);
            }
            Err(e) => {
                error!("Failed to write to stdin: {:?}", e);
            }
        }

    }

    fn create_pseudo_console() ->  io::Result<PtyPair> {

        // maybe make whole function body unsafe so I dont have to declare it more than once
        let (stdin_read, stdout_write,stdout_read, stdin_write) = Self::create_pipe_handles();
        // we are not spawning a console but it is still needed  (the size)
        const DEFAULT_CONSOLE_SIZE: COORD = COORD { X: 80, Y: 80 }; 
        let hpc: HPCON = unsafe { CreatePseudoConsole(DEFAULT_CONSOLE_SIZE, stdin_read, stdout_write, 0)? };

        if hpc.is_invalid() {
            return Err(io::Error::new(io::ErrorKind::Other, "Failed to create pseudoconsole"));
        }


        let master = Master { read: Arc::new(Mutex::new(stdout_read)), write: Arc::new(Mutex::new(stdin_write)) };
        let slave = Slave { read: stdin_read, write: stdout_write };

        let (process_info, handle_job)  = Self::start_main_process(master.clone(), Self::allocate_startup_info(&hpc).unwrap());

         unsafe {
            let _ = CloseHandle(stdout_write); 
        }

        let pair = PtyPair { master: master.clone(), slave: slave.clone(), hpc, process_info, h_job: handle_job };
        Ok(pair)

    }

    fn allocate_startup_info(hpc: &HPCON) ->  io::Result<STARTUPINFOEXW> {
        let mut si_ex = STARTUPINFOEXW::default();
        si_ex.StartupInfo.cb = size_of::<STARTUPINFOEXW>() as u32;

        let mut bytes_required =  0;

        unsafe { 
            let _ = InitializeProcThreadAttributeList(
                    None,          
                    1,
                    None,             
                    &mut bytes_required as *mut usize,
                ).ok();


            let heap = GetProcessHeap()?;
            let raw_ptr = HeapAlloc(heap, HEAP_ZERO_MEMORY, bytes_required);

            if raw_ptr.is_null() {
                return Err(io::Error::new(io::ErrorKind::Other, "HeapAlloc failed"));
            }

            si_ex.lpAttributeList = LPPROC_THREAD_ATTRIBUTE_LIST(raw_ptr as *mut c_void);


            println!("bytes_required: {}", bytes_required);

            if si_ex.lpAttributeList.is_invalid(){
                return Err(io::Error::new(io::ErrorKind::Other, "Failed to allocate memory for attribute list"));
            }

            let init_proc =
                InitializeProcThreadAttributeList(  
                     Some(si_ex.lpAttributeList),
                    1,
                    Some(0),
                    &mut bytes_required as *mut usize,
                );

            match init_proc {
                Ok(_) => info!("Attribute list initialized successfully."),
                Err(e) => {
                    error!("Failed to initialize attribute list: {:?}", e);
                    // You can get the error code too
                    error!("HRESULT: {:?}", e.code());
                }
            }

            // print hpc
            info!("Pseudoconsole handle: {:?}", hpc);

            let update_proc_attr = UpdateProcThreadAttribute(
                    si_ex.lpAttributeList,
                    0,
                    PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE as usize, // PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE
                    Some(hpc.0 as *mut c_void),
                    size_of::<HPCON>(),
                    None,
                    None,
                );


            match update_proc_attr {
                Ok(_) => info!("Pseudoconsole handle added to attribute list."),
                Err(e) => {
                    error!("Failed to initialize attribute list: {:?}", e);
                    return Err(io::Error::new(io::ErrorKind::Other, "Failed to update attribute list"));
            }
        };

    
    };

        Ok(si_ex)
        
    }

    fn get_subprocess_pid(&self) -> u32 {
        let pids = Self::get_job_process_list(self.h_job);
        let parent_pid = self.process_info.dwProcessId;

        // Filter out the parent PID (powershell.exe itself)
        for pid in pids {
            if pid != parent_pid {
                println!("Subprocess in job: PID = {}", pid);
                return pid;
            }
        }

        0
    }

    // this is what wrapping our process in an Object allows us to do (nice grouping I like it miam)
    fn get_job_process_list(h_job: HANDLE) -> Vec<u32> {
        let size = std::mem::size_of::<JOBOBJECT_BASIC_PROCESS_ID_LIST>() + std::mem::size_of::<usize>() * 16;
        let mut buffer = vec![0u8; size];

        unsafe {
            let result = QueryInformationJobObject(
                Some(h_job),
                JobObjectBasicProcessIdList,
                buffer.as_mut_ptr() as *mut _,
                size as u32,
                Some(null_mut()),
            );

            if !result.is_ok() {
                error!("Failed to query job object info: {:?}", GetLastError());
                return vec![];
            }

            let list: &JOBOBJECT_BASIC_PROCESS_ID_LIST = &*(buffer.as_ptr() as *const _);
            let count = list.NumberOfProcessIdsInList as usize;
            let pids_ptr = list.ProcessIdList.as_ptr();
            let pids = std::slice::from_raw_parts(pids_ptr as *const usize, count);
            return pids.iter().map(|pid| *pid as u32).collect();
        }
    }

    fn start_main_process(master: Master, si: STARTUPINFOEXW) -> (PROCESS_INFORMATION, HANDLE) {
       let mut cmdline: Vec<u16> = "powershell.exe -NoExit -NoLogo -NoProfile"
        .encode_utf16()
        .chain(std::iter::once(0)) // null-terminated for Windows API
        .collect();
        let mut process_info: PROCESS_INFORMATION = PROCESS_INFORMATION::default();

        // WE NEED TO MAKE THIS WORK IF WE WANT ENVS to be passed.

        let env_vars = Self::collect_os_vars();

        let success = unsafe {
            CreateProcessW(
                None,
                Some(PWSTR(cmdline.as_mut_ptr())),
                None,
                None,
                TRUE.as_bool(),
                EXTENDED_STARTUPINFO_PRESENT | CREATE_NEW_PROCESS_GROUP,
                None,
                None,
                &si.StartupInfo,
                &mut process_info,
            )
        };

        // Adding our powershell to a JobObject allows us to get child processes "more easily"
        let h_job = unsafe { CreateJobObjectW(None, None) }.unwrap_or_else(|e| {
            error!("Failed to create job object: {:?}", e);
            panic!("Failed to create job object");
        });

        unsafe {
            AssignProcessToJobObject(h_job, process_info.hProcess).unwrap();
        }

        match success {
            Ok(_) => {
                info!("Process created successfully.");


                        // spawning the reading thread in another thread
                        let master_for_thread = master.clone();
                        std::thread::sleep(std::time::Duration::from_millis(1000)); // allow time for initialization

                        thread::spawn(move || {
                            let result = std::panic::catch_unwind(|| {
                                Self::read_master_stdout(master_for_thread);
                            });
                            if let Err(e) = result {
                                println!("read_master_stdout panicked: {:?}", e);
                            }
                    });

                // unsafe {
                //         WaitForSingleObject(process_info.hProcess, INFINITE);
                //         // let mut exit_code = 0;
                //         // let _ = GetExitCodeProcess(process_info.hProcess, &mut exit_code);
                //         // debug!("Child process exit code: {}", exit_code);

                //         // if exit_code != 0 {
                //         //     let error_code = GetLastError();
                //         //     error!("Process failed with exit code: {}, Error Code: {:?}", exit_code, error_code);
                //         // }
                //     }; 
            }


            Err(e) => {
                error!("Failed to create process: {:?}", e);
                error!("HRESULT: {:?}", e.code());
            }
        }
        
        unsafe {
            DeleteProcThreadAttributeList(si.lpAttributeList);
            let _ = HeapFree(GetProcessHeap().unwrap(), windows::Win32::System::Memory::HEAP_FLAGS(0), Some(si.lpAttributeList.0 as *const c_void));
        }

        return (process_info, h_job);
    }
    
    fn resize_pseudo_console(self: Self, size: COORD) {
        let result = unsafe { ResizePseudoConsole(self.hpc, size) };
        if result.is_ok() {
            info!("Pseudo console resized successfully.");
        } else {
            error!("Failed to resize pseudo console: {:?}", result);
        }
    }

    fn collect_os_vars() -> Option<*const c_void> {


        use std::os::windows::ffi::OsStrExt;
            let mut env: Vec<u16> = std::env::vars_os()
        .flat_map(|(k, v)| {
            let mut pair = k.encode_wide().collect::<Vec<_>>(); // Use encode_wide here
            pair.push('=' as u16);
            pair.extend(v.encode_wide()); // Use encode_wide here
            pair.push(0);
            pair
        }).chain(std::iter::once(0))
        .collect();


        if !std::env::vars_os().any(|(k, _)| k == "PATH") {
            let path = std::env::var_os("PATH").unwrap_or_default();
            let mut path_pair = "PATH=".encode_utf16().collect::<Vec<_>>();
            path_pair.extend(path.encode_wide());
            path_pair.push(0);
            env.extend(path_pair);
        }
        env.push(0);

        let env_ptr: Option<*const c_void> = if env.is_empty() { None } else { Some(env.as_ptr() as *const c_void) };
        env_ptr
    }

    #[allow(dead_code)]
    fn check_handle_flags(handle: HANDLE) {
        let mut flags = 0;
        let result = unsafe { GetHandleInformation(handle, &mut flags) };
        if result.is_ok() {
            info!("Handle flags: {:?}", flags);
        } else {
            error!("Failed to get handle information: {:?}", result);
        }
    }

    fn create_pipe_handles() -> (HANDLE, HANDLE, HANDLE, HANDLE) {
        let mut stdin_read = HANDLE(null_mut());
        let mut stdin_write = HANDLE(null_mut());
        let mut stdout_read = HANDLE(null_mut());
        let mut stdout_write = HANDLE(null_mut());

        let sa = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>()  as u32,
            lpSecurityDescriptor: null_mut(),
            bInheritHandle: TRUE 
        };

        let stdin_pipe = unsafe { CreatePipe(&mut stdin_read, &mut stdin_write, Some(&sa), 0) };
        let stdout_pipe = unsafe { CreatePipe(&mut stdout_read, &mut stdout_write, Some(&sa), 0) };

        info!("stdin_read: {:?}", stdin_read);
        info!("stdin_write: {:?}", stdin_write);
        info!("stdout_read: {:?}", stdout_read);
        info!("stdout_write: {:?}", stdout_write);

        unsafe {
            let _ = SetHandleInformation(stdin_write, HANDLE_FLAG_INHERIT.0, HANDLE_FLAG_INHERIT);
            let _ = SetHandleInformation(stdout_read, HANDLE_FLAG_INHERIT.0, HANDLE_FLAG_INHERIT);
        }

        match stdin_pipe {
            Ok(_) => info!("handle one created successfully."),
            Err(e) => {
                error!("Failed to create handle : {:?}", e);
                // You can get the error code too
                error!("HRESULT: {:?}", e.code());
            }
        }

        match stdout_pipe {
            Ok(_) => info!("handle two created successfully."),
            Err(e) => {
                error!("Failed to create handle : {:?}", e);
                // You can get the error code too
                error!("HRESULT: {:?}", e.code());
            }
        }

        (stdin_read, stdout_write, stdout_read, stdin_write)
    }

}

use once_cell::sync::Lazy;
static PTY: Lazy<Mutex<Option<PtyPair>>> = Lazy::new(|| Mutex::new(None));
type AppResult<T> = std::result::Result<T, String>;

#[tauri::command]
fn start_terminal() -> AppResult<String> {
    let mut pty_guard = PTY.lock().unwrap();
    if pty_guard.is_none() {
        *pty_guard = Some(PtyPair::new());
        println!("PTY initialized");
    }
    Ok("Terminal started".to_string())
}

#[tauri::command]
fn send_pty_cmd(cmd: &str) -> AppResult<String> {

    println!("Sending command: {}", cmd);
    let pty_guard = PTY.lock().unwrap();
    if let Some(ref pty) = *pty_guard {
        pty.write(cmd);
        Ok("Command sent".to_string())
    } else {
        Err("PTY not initialized".to_string())
    }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .invoke_handler(tauri::generate_handler![start_terminal, send_pty_cmd])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
