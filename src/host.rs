use nix::sys::uio::{RemoteIoVec, process_vm_readv, process_vm_writev};
use nix::unistd::Pid;
use std::fs;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::io::{IoSlice, IoSliceMut};
use std::path::PathBuf;

use crate::backend::MemoryOps;
use crate::types::PhysAddr;

struct MemoryRegion {
    start: u64,
    end: u64,
    length: u64,
}

pub struct KvmHandle {
    memory: MemoryRegion,
    pid: Pid,
}

/*
 * TODO (possibly?)
 * 1. rename KvmHandle to KvmProcess
 * 2. add new type, KvmSharedMemory
 * 2a. this new type will work in conjuction with QEMU's shared memory feature
 * 2b. this new type will allow us to use mmap and access memory directly, instead of process_vm_read/write
 * 3. ensure all APIs within this repos are using MemoryOps, not KvmHandle..
 * 4. if we are keeping KvmProcess instead of forcing users to use shared memory (so keep a safe fallback),
 *    we must not allow copies outside of the memory backend. the issue is that with a shared memory map,
 *    the debugger has immediate access to all memory and doesn't need to reread any blocks. however, with
 *    the process_vm approach, we need to copy memory from the KVM process to the debugger. the code outside
 *    of the MemoryOps must be agnostic, and it wouldn't make sense for both backends to be implemented
 *    and have shared memory NOT be zero-copy. this means that, somehow, KvmProcess will also have to expose
 *    zero-copy functions, likely by making it so copies will occur internally. this would solve the issue
 *    of having many `mut`s scattered about, because we are copying data when data copy should not have
 *    been exposed to begin with...
 */

fn get_kvm_pid() -> Result<i32, String> {
    for entry in fs::read_dir("/proc").map_err(|_| "failed to open /proc".to_string())? {
        let entry = match entry {
            Ok(e) => e,
            Err(_) => continue,
        };

        if !entry.path().is_dir() {
            continue;
        }

        let fd_path = entry.path().join("fd");
        let fd_iter = match fs::read_dir(&fd_path) {
            Ok(iter) => iter,
            Err(_) => continue,
        };

        for fd_entry in fd_iter {
            let fd_entry = match fd_entry {
                Ok(e) => e,
                Err(_) => continue,
            };

            if let Ok(target) = fs::read_link(fd_entry.path()) {
                if target == PathBuf::from("/dev/kvm") {
                    if let Some(pid_str) = entry.file_name().to_str() {
                        if let Ok(pid) = pid_str.parse::<i32>() {
                            return Ok(pid);
                        }
                    }
                }
            }
        }
    }

    Err("failed to find kvm".into())
}

fn get_kvm_primary_memory(pid: i32) -> Result<MemoryRegion, String> {
    let maps = File::open(format!("/proc/{}/maps", pid)).map_err(|_| "failed to open kvm maps")?;
    let reader = BufReader::new(maps);

    let region = reader
        .lines()
        .filter_map(|line| line.ok())
        .filter_map(|line| {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.is_empty() {
                return None;
            }

            let addresses: Vec<&str> = parts[0].split('-').collect();
            if addresses.len() != 2 {
                return None;
            }

            let start = u64::from_str_radix(addresses[0], 16).ok()?;
            let end = u64::from_str_radix(addresses[1], 16).ok()?;

            Some(MemoryRegion {
                start,
                end,
                length: end - start,
            })
        })
        .max_by_key(|region| region.length)
        .ok_or("no memory regions found in kvm")?;

    Ok(region)
}

fn kfix(x: u64) -> u64 {
    if x < 0x80000000 {
        return x;
    }

    x - 0x80000000
}

impl KvmHandle {
    pub fn new() -> Result<Self, String> {
        let pid = get_kvm_pid()?;
        let memory = get_kvm_primary_memory(pid)?;

        Ok(Self {
            memory,
            pid: Pid::from_raw(pid),
        })
    }
}

impl MemoryOps<PhysAddr> for KvmHandle {
    fn read_bytes(&self, addr: PhysAddr, buf: &mut [u8]) -> Result<usize, String> {
        let remote_iov = RemoteIoVec {
            base: (self.memory.start + kfix(addr.0)) as usize,
            len: buf.len(),
        };

        let local_iov = IoSliceMut::new(buf);

        process_vm_readv(self.pid, &mut [local_iov], &[remote_iov]).map_err(|e| {
            format!(
                "could not read physical address {:x} ({})",
                addr.0,
                e.to_string()
            )
        })
    }

    fn write_bytes(&self, addr: PhysAddr, buf: &[u8]) -> Result<usize, String> {
        let remote_iov = RemoteIoVec {
            base: (self.memory.start + kfix(addr.0)) as usize,
            len: buf.len(),
        };

        let local_iov = IoSlice::new(buf);

        process_vm_writev(self.pid, &mut [local_iov], &[remote_iov]).map_err(|e| e.to_string())
    }
}
