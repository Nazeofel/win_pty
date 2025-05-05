use std::{ffi::CString, io::{self, Write}, process::exit, ptr::null_mut};

use winapi::um::{fileapi::{ReadFile, WriteFile}, handleapi::{CloseHandle, SetHandleInformation}, minwinbase::SECURITY_ATTRIBUTES, processthreadsapi::{CreateProcessA, PROCESS_INFORMATION, STARTUPINFOA}, securitybaseapi::{AddAccessAllowedAce, AllocateAndInitializeSid, FreeSid, InitializeAcl, InitializeSecurityDescriptor, SetSecurityDescriptorDacl}, winbase::HANDLE_FLAG_INHERIT, winnt::{ACCESS_ALLOWED_ACE, ACL, ACL_REVISION, GENERIC_ALL, PACL, SECURITY_DESCRIPTOR, SID, SID_IDENTIFIER_AUTHORITY}};
use winapi::um::namedpipeapi::CreatePipe;
use winapi::um::winnt::HANDLE;
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

impl Drop for PtyPair {
    fn drop(&mut self) {
        unsafe {
            // Close all pipe handles
            if !self.master.read.is_null() {
                CloseHandle(self.master.read);
            }
            if !self.master.write.is_null() {
                CloseHandle(self.master.write);
            }
            if !self.slave.read.is_null() {
                CloseHandle(self.slave.read);
            }
            if !self.slave.write.is_null() {
                CloseHandle(self.slave.write);
            }
        }
    }
}

impl PtyPair {
    fn new() -> Self {
        let pair = Self::create_pipe().unwrap();
        let master = pair.master.clone();
        let slave =  pair.slave.clone();
        Self::start_cmd(master.clone(), &slave);
        PtyPair { master, slave }
    }

    fn write(self: &Self, data: &str) {
        Self::master_stdin(self.master.clone(), self.slave.clone(), data);
        
    }

    // Everytime it is ran (in the future) I need to return JSONValue (from serde)
    fn read_master_stdout(master: Master) { 
        let buf_size = 8192; // More reasonable buffer size
        let mut buffer = vec![0; buf_size];
        
        loop {
            let mut bytes_read = 0;
            
            let success_read = unsafe { 
                ReadFile(
                    master.read,
                    buffer.as_mut_ptr() as *mut _,
                    buffer.len() as u32,
                    &mut bytes_read,
                    null_mut()
                ) 
            };

            if success_read == 0 {
                let err = io::Error::last_os_error();
                eprintln!("Failed to read output: {}", err);
                // Check if pipe is broken or closed
                if err.kind() == io::ErrorKind::BrokenPipe {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(100));
                continue;
            }
            
            // If we read 0 bytes, the pipe might be closed
            if bytes_read == 0 {
                break;
            }
            
            // Convert the read bytes to a string and print it
            if let Ok(str) = String::from_utf8(buffer[..bytes_read as usize].to_vec()) {
                print!("{}", str); // Using print! instead of println! to respect line endings
                io::stdout().flush().unwrap(); // Make sure output appears immediately
            } else {
                // Handle non-UTF8 output if needed
                print!("{}", String::from_utf8_lossy(&buffer[..bytes_read as usize]));
                io::stdout().flush().unwrap();
            }
        }
    }

    fn master_stdin(master: Master, slave: Slave, data: &str) {
        let mut bytes_written = 0;
        let success = unsafe { WriteFile(
            master.write,
            data.as_ptr() as *const _,
            data.len() as u32,
            &mut bytes_written,
            null_mut(),
        ) };

        if success == 0 {
           exit(0)
        }
    }

    fn start_cmd(master: Master, slave: &Slave) -> PROCESS_INFORMATION {
        let cmd = CString::new("C:\\Windows\\System32\\cmd.exe").unwrap();
        let cmdline = CString::new("cmd.exe /Q /K prompt $G & @echo off").unwrap(); // Quiet + no prompt + echo off
        let mut startup_info: STARTUPINFOA = unsafe { std::mem::zeroed() };
        let mut process_info: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };
    
        startup_info.cb = std::mem::size_of::<STARTUPINFOA>() as u32;
        startup_info.hStdInput = slave.read;
        startup_info.hStdOutput = slave.write;
        startup_info.hStdError = slave.write;
        startup_info.dwFlags = 0x00000100;
    
        let success = unsafe {
            CreateProcessA(
                cmd.as_ptr(),
                cmdline.as_ptr() as *mut i8,
                null_mut(),
                null_mut(),
                1,
                0,
                null_mut(),
                null_mut(),
                &mut startup_info,
                &mut process_info,
            )
        };
    
        if success == 0 {
            panic!("Failed to launch cmd.exe");
        }

        let master_for_thread = master.clone();
        
        // Spawn a new thread to handle reading from the master
        std::thread::spawn(move || {
            Self::read_master_stdout(master_for_thread);
        });

        process_info
    }

    fn create_pipe() ->  io::Result<PtyPair> {
        unsafe {
            let mut everyone_sid: *mut SID = null_mut();
            let world_auth = SID_IDENTIFIER_AUTHORITY { Value: [0, 0, 0, 0, 0, 1] };
            if  AllocateAndInitializeSid(
                &world_auth as *const _ as *mut _,
                1,
                0x00000000,
                0, 0, 0, 0, 0, 0, 0,
                &mut everyone_sid as *const _ as *mut _,
            ) == 0 {
             return Err(io::Error::last_os_error());
            }
    
            // // Step 3: Create an ACL and set GENERIC_ALL access
    
           let mem_acl_size = std::mem::size_of::<ACL>() + std::mem::size_of::<ACCESS_ALLOWED_ACE>() + 16;
            let mut acl_buffer: Vec<u8> = vec![0; mem_acl_size]; // Zero-initialized buffer
            let acl: PACL = acl_buffer.as_mut_ptr() as PACL; // Convert to PACL
    
            if InitializeAcl(acl, mem_acl_size  as u32, ACL_REVISION.into()) == 0 {
                eprintln!("Failed to initialize ACL");
                return Err(io::Error::last_os_error());
            }
    
            //Add an access allowed ACE to the ACL with GENERIC_ALL permissions
            if AddAccessAllowedAce(acl, ACL_REVISION.into(), GENERIC_ALL, everyone_sid as *const _ as *mut _ ) == 0 {
                return Err(io::Error::last_os_error());
                }
    
    
            // Step 4: Initialize a security descriptor and set the DACL
            let mut security_descriptor: SECURITY_DESCRIPTOR =  std::mem::zeroed() ;
                    if InitializeSecurityDescriptor(&mut security_descriptor as *const _ as *mut _, 1)  == 0 {
                return Err(io::Error::last_os_error());
            }
    
            if SetSecurityDescriptorDacl(&mut security_descriptor as *const _ as *mut _, 1, acl, 0)  == 0 {
                eprintln!("Failed to set security descriptor DACL");
                            return Err(io::Error::last_os_error());
    
                }
    
            let mut sa = SECURITY_ATTRIBUTES {
                    nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>()  as u32,
                    lpSecurityDescriptor: &security_descriptor as *const _ as *mut _,
                    bInheritHandle: 1 // 1 means the handle can be inherited by child processes
                };

            FreeSid(everyone_sid as *const _ as *mut _);
    
            // Create stdin pipe (parent writes, child reads)
            let mut stdin_read = null_mut();
            let mut stdin_write = null_mut();

            if CreatePipe(&mut stdin_read, &mut stdin_write, &mut sa, 0) == 0 {
                // better error needed probably
                exit(0);
            };

           if SetHandleInformation(stdin_write, HANDLE_FLAG_INHERIT, 0) == 0 {
                // better error needed probably
                CloseHandle(stdin_read);
                CloseHandle(stdin_write);
                exit(0);
           }; 

            // Create stdout pipe (child writes, parent reads)
            let mut stdout_read = null_mut();
            let mut stdout_write = null_mut();


           if CreatePipe(&mut stdout_read, &mut stdout_write, &mut sa, 0) == 0 {
             // better error needed probably
                exit(0);
           };
            if SetHandleInformation(stdout_read, HANDLE_FLAG_INHERIT, 0) == 0 {
                 // better error needed probably
                 CloseHandle(stdin_read);
                 CloseHandle(stdin_write);
                 CloseHandle(stdout_read);
                 CloseHandle(stdout_write);
                 exit(0);
            };
    
    
            return Ok(PtyPair {
                master: { Master { read: stdout_read, write: stdin_write }}, 
                slave: Slave { read: stdin_read, write: stdout_write } 
            });
    
            }
    
    }
}

fn main() {
    
    let pair = PtyPair::new();  

    let stdin = io::stdin();
    let mut input = String::new();
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
