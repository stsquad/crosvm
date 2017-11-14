// Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::ffi::CStr;
use std::fs::File;
use std::io::{Seek, SeekFrom};
use std::os::unix::io::{AsRawFd, IntoRawFd, FromRawFd, RawFd};

use libc::{self, off64_t, c_long, c_int, c_uint, c_char, close, syscall, ftruncate64};

use errno;
use syscall_defines::linux::LinuxSyscall::SYS_memfd_create;

use {Result, errno_result};

/// A shared memory file descriptor and its size.
pub struct SharedMemory {
    fd: File,
    size: u64,
}

// from <sys/memfd.h>
const MFD_CLOEXEC: c_uint = 0x0001;

unsafe fn memfd_create(name: *const c_char, flags: c_uint) -> c_int {
    syscall(SYS_memfd_create as c_long, name as i64, flags as i64) as c_int
}

impl SharedMemory {
    /// Creates a new shared memory file descriptor with zero size.
    ///
    /// If a name is given, it will appear in `/proc/self/fd/<shm fd>` for the purposes of
    /// debugging. The name does not need to be unique.
    ///
    /// The file descriptor is opened with the close on exec flag.
    pub fn new(name: Option<&CStr>) -> Result<SharedMemory> {
        let shm_name = name.map(|n| n.as_ptr())
            .unwrap_or(b"/crosvm_shm\0".as_ptr() as *const c_char);
        // The following are safe because we give a valid C string and check the
        // results of the memfd_create call.
        let fd = unsafe { memfd_create(shm_name, MFD_CLOEXEC) };
        if fd < 0 {
            return errno_result();
        }

        let file = unsafe { File::from_raw_fd(fd) };

        Ok(SharedMemory { fd: file, size: 0 })
    }

    /// Constructs a `SharedMemory` instance from a file descriptor that represents shared memory.
    ///
    /// The size of the resulting shared memory will be determined using `File::seek`. If the given
    /// file's size can not be determined this way, this will return an error.
    pub fn from_raw_fd<T: IntoRawFd>(fd: T) -> Result<SharedMemory> {
        // Safe because the IntoRawFd trait indicates fd has unique ownership.
        let mut file = unsafe { File::from_raw_fd(fd.into_raw_fd()) };
        let file_size = file.seek(SeekFrom::End(0))?;
        Ok(SharedMemory {
               fd: file,
               size: file_size as u64,
           })
    }

    /// Gets the size in bytes of the shared memory.
    ///
    /// The size returned here does not reflect changes by other interfaces or users of the shared
    /// memory file descriptor..
    pub fn size(&self) -> u64 {
        self.size
    }

    /// Sets the size in bytes of the shared memory.
    ///
    /// Note that if some process has already mapped this shared memory and the new size is smaller,
    /// that process may get signaled with SIGBUS if they access any page past the new size.
    pub fn set_size(&mut self, size: u64) -> Result<()> {
        let ret = unsafe { ftruncate64(self.fd.as_raw_fd(), size as off64_t) };
        if ret < 0 {
            return errno_result();
        }
        self.size = size;
        Ok(())
    }
}

impl AsRawFd for SharedMemory {
    fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}

/// Checks if the kernel we are running on has memfd_create. It was introduced in 3.17.
/// Only to be used from tests to prevent running on ancient kernels that won't
/// support the functionality anyways.
pub fn kernel_has_memfd() -> bool {
    unsafe {
        let fd = memfd_create(b"/test_memfd_create\0".as_ptr() as *const c_char, 0);
        if fd < 0 {
            if errno::Error::last().errno() == libc::ENOSYS {
                return false;
            }
            return true;
        }
        close(fd);
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::ffi::CString;
    use std::fs::read_link;
    use std::io::repeat;

    use data_model::VolatileMemory;

    use MemoryMapping;

    #[test]
    fn new() {
        if !kernel_has_memfd() { return; }
        let shm = SharedMemory::new(None).expect("failed to create shared memory");
        assert_eq!(shm.size(), 0);
    }

    #[test]
    fn new_sized() {
        if !kernel_has_memfd() { return; }
        let mut shm = SharedMemory::new(None).expect("failed to create shared memory");
        shm.set_size(1024)
            .expect("failed to set shared memory size");
        assert_eq!(shm.size(), 1024);
    }

    #[test]
    fn new_huge() {
        if !kernel_has_memfd() { return; }
        let mut shm = SharedMemory::new(None).expect("failed to create shared memory");
        shm.set_size(0x7fff_ffff_ffff_ffff)
            .expect("failed to set shared memory size");
        assert_eq!(shm.size(), 0x7fff_ffff_ffff_ffff);
    }

    #[test]
    fn new_too_huge() {
        if !kernel_has_memfd() { return; }
        let mut shm = SharedMemory::new(None).expect("failed to create shared memory");
        shm.set_size(0x8000_0000_0000_0000).unwrap_err();
        assert_eq!(shm.size(), 0);
    }

    #[test]
    fn new_named() {
        if !kernel_has_memfd() { return; }
        let name = "very unique name";
        let cname = CString::new(name).unwrap();
        let shm = SharedMemory::new(Some(&cname)).expect("failed to create shared memory");
        let fd_path = format!("/proc/self/fd/{}", shm.as_raw_fd());
        let link_name =
            read_link(fd_path).expect("failed to read link of shared memory /proc/self/fd entry");
        assert!(link_name.to_str().unwrap().contains(name));
    }

    #[test]
    fn mmap_page() {
        if !kernel_has_memfd() { return; }
        let mut shm = SharedMemory::new(None).expect("failed to create shared memory");
        shm.set_size(4096)
            .expect("failed to set shared memory size");

        let mmap1 =
            MemoryMapping::from_fd(&shm, shm.size() as usize).expect("failed to map shared memory");
        let mmap2 =
            MemoryMapping::from_fd(&shm, shm.size() as usize).expect("failed to map shared memory");

        assert_ne!(mmap1.get_slice(0, 1).unwrap().as_ptr(),
                   mmap2.get_slice(0, 1).unwrap().as_ptr());

        mmap1
            .get_slice(0, 4096)
            .expect("failed to get mmap slice")
            .read_from(&mut repeat(0x45))
            .expect("failed to fill mmap slice");

        for i in 0..4096 {
            assert_eq!(mmap2.get_ref::<u8>(i).unwrap().load(), 0x45u8);
        }
    }
}
