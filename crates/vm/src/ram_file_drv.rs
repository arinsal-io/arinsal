//! Linked-in `ram_file_drv` port driver.
//!
//! Port of `erts/emulator/drivers/common/ram_file_drv.c`, OTP-29.1.1.

use std::sync::{Arc, Mutex};

use crate::port::PortHandle;

const RAM_FILE_OPEN: u8 = 1;
const RAM_FILE_READ: u8 = 2;
const RAM_FILE_LSEEK: u8 = 3;
const RAM_FILE_WRITE: u8 = 4;
const RAM_FILE_FSYNC: u8 = 9;
const RAM_FILE_TRUNCATE: u8 = 14;
const RAM_FILE_PREAD: u8 = 17;
const RAM_FILE_PWRITE: u8 = 18;
const RAM_FILE_FDATASYNC: u8 = 19;
const RAM_FILE_GET: u8 = 30;
const RAM_FILE_SIZE: u8 = 37;
const RAM_FILE_ADVISE: u8 = 38;
const RAM_FILE_ALLOCATE: u8 = 39;

const RAM_FILE_MODE_READ: i32 = 1;
const RAM_FILE_MODE_WRITE: i32 = 2;
const RAM_FILE_SEEK_SET: i32 = 0;
const RAM_FILE_SEEK_CUR: i32 = 1;
const RAM_FILE_SEEK_END: i32 = 2;

const RAM_FILE_RESP_OK: u8 = 0;
const RAM_FILE_RESP_ERROR: u8 = 1;
const RAM_FILE_RESP_DATA: u8 = 2;
const RAM_FILE_RESP_NUMBER: u8 = 3;

const BFILE_BLOCK: i64 = 1024;
const BUFFER_SLACK: i64 = BFILE_BLOCK + (BFILE_BLOCK >> 1);

struct RamFile {
    flags: i32,
    buffer: Vec<u8>,
    position: i64,
    end: i64,
}

/// Per-port driver data, stored in the owning [`PortHandle`].
// erts keeps this in the `RamFile` that `rfile_start` allocates as the port's `drv_data`.
pub(crate) struct RamPort {
    file: Mutex<RamFile>,
    binary: bool,
}

/// Create the state allocated by `rfile_start`.
// Port of erts/emulator/drivers/common/ram_file_drv.c:173-187 (rfile_start), OTP-29.1.1.
pub(crate) fn start(binary: bool) -> Arc<RamPort> {
    Arc::new(RamPort {
        file: Mutex::new(RamFile {
            flags: 0,
            buffer: Vec::new(),
            position: 0,
            end: 0,
        }),
        binary,
    })
}

/// Run one `rfile_command` and deliver its encoded driver reply to the connected process.
// Port of erts/emulator/drivers/common/ram_file_drv.c:397-531 (rfile_command), OTP-29.1.1.
pub(crate) fn command(port: &RamPort, handle: &PortHandle, bytes: &[u8]) -> Result<(), ()> {
    let Some((&op, args)) = bytes.split_first() else {
        return Ok(());
    };
    let mut file = port.file.lock().unwrap();
    if let Some(reply) = command_file(&mut file, op, args) {
        if matches!(op, RAM_FILE_READ | RAM_FILE_PREAD | RAM_FILE_GET)
            && reply.first() == Some(&RAM_FILE_RESP_DATA)
        {
            crate::port::static_driver_output_binary(handle, &reply[..5], &reply[5..], port.binary);
        } else {
            crate::port::static_driver_output(handle, &reply);
        }
    }
    Ok(())
}

// Port of erts/emulator/drivers/common/ram_file_drv.c:397-531 (rfile_command), OTP-29.1.1.
fn command_file(file: &mut RamFile, op: u8, args: &[u8]) -> Option<Vec<u8>> {
    match op {
        RAM_FILE_OPEN => {
            let Some((mode, data)) = args.split_at_checked(4) else {
                return Some(error_reply(libc::EINVAL));
            };
            file.flags = i32::from_be_bytes(mode.try_into().unwrap());
            match init(file, data) {
                Ok(()) => Some(number_reply(0)),
                Err(error) => Some(error_reply(error)),
            }
        }
        RAM_FILE_FDATASYNC | RAM_FILE_FSYNC => {
            if file.flags == 0 {
                Some(error_reply(libc::EBADF))
            } else {
                Some(ok_reply())
            }
        }
        RAM_FILE_WRITE => match write(file, args, None) {
            Ok(count) => Some(number_reply(count as i64)),
            Err(error) => Some(error_reply(error)),
        },
        RAM_FILE_PWRITE => {
            let Some((offset, data)) = args.split_at_checked(4) else {
                return Some(error_reply(libc::EINVAL));
            };
            let offset = i32::from_be_bytes(offset.try_into().unwrap());
            if offset < 0 {
                Some(error_reply(libc::EINVAL))
            } else {
                match write(file, data, Some(i64::from(offset))) {
                    Ok(count) => Some(number_reply(count as i64)),
                    Err(error) => Some(error_reply(error)),
                }
            }
        }
        RAM_FILE_LSEEK => {
            let Some((offset, origin)) = args.split_at_checked(4) else {
                return Some(error_reply(libc::EINVAL));
            };
            let Some(origin) = origin.get(..4) else {
                return Some(error_reply(libc::EINVAL));
            };
            let offset = i32::from_be_bytes(offset.try_into().unwrap());
            let origin = i32::from_be_bytes(origin.try_into().unwrap());
            match seek(file, i64::from(offset), origin) {
                Ok(position) => Some(number_reply(position)),
                Err(error) => Some(error_reply(error)),
            }
        }
        RAM_FILE_PREAD => {
            let Some((offset, rest)) = args.split_at_checked(4) else {
                return Some(error_reply(libc::EINVAL));
            };
            let Some(length) = rest.get(..4) else {
                return Some(error_reply(libc::EINVAL));
            };
            let offset = i32::from_be_bytes(offset.try_into().unwrap());
            if offset < 0 {
                return Some(error_reply(libc::EINVAL));
            }
            let length = i32::from_be_bytes(length.try_into().unwrap());
            match read(file, i64::from(length), Some(i64::from(offset))) {
                Ok(data) => Some(data_reply(&data)),
                Err(error) => Some(error_reply(error)),
            }
        }
        RAM_FILE_READ => {
            let Some(length) = args.get(..4) else {
                return Some(error_reply(libc::EINVAL));
            };
            let length = i32::from_be_bytes(length.try_into().unwrap());
            match read(file, i64::from(length), None) {
                Ok(data) => Some(data_reply(&data)),
                Err(error) => Some(error_reply(error)),
            }
        }
        RAM_FILE_TRUNCATE => {
            if file.flags & RAM_FILE_MODE_WRITE == 0 {
                Some(error_reply(libc::EACCES))
            } else {
                let end = file.end;
                let position = file.position;
                if end > position
                    && let Some(zeroes) = file.buffer.get_mut(
                        usize::try_from(position).unwrap_or(usize::MAX)
                            ..usize::try_from(end).unwrap_or(usize::MAX),
                    )
                {
                    zeroes.fill(0);
                }
                file.end = position;
                Some(ok_reply())
            }
        }
        RAM_FILE_GET => {
            let end = usize::try_from(file.end).ok()?;
            let Some(data) = file.buffer.get(..end) else {
                return Some(error_reply(libc::ENOMEM));
            };
            Some(data_reply(data))
        }
        RAM_FILE_SIZE => Some(number_reply(file.end)),
        RAM_FILE_ADVISE | RAM_FILE_ALLOCATE => {
            if file.flags == 0 {
                Some(error_reply(libc::EBADF))
            } else {
                Some(ok_reply())
            }
        }
        // C leaves SET, GET_CLOSE, compress, uncompress and uuencode opcodes disabled.
        _ => None,
    }
}

// Port of erts/emulator/drivers/common/ram_file_drv.c:262-288 (ram_file_init), OTP-29.1.1.
fn init(file: &mut RamFile, data: &[u8]) -> Result<(), i32> {
    let count = i64::try_from(data.len()).map_err(|_| libc::EINVAL)?;
    let size = allocation_size(count)?;
    let buffer = zeroed(size)?;
    if buffer.len() < data.len() {
        return Err(libc::EINVAL);
    }
    let mut buffer = buffer;
    buffer[..data.len()].copy_from_slice(data);
    file.buffer = buffer;
    file.position = 0;
    file.end = count;
    Ok(())
}

// Port of erts/emulator/drivers/common/ram_file_drv.c:290-317 (ram_file_expand), OTP-29.1.1.
fn expand(file: &mut RamFile, size: i64) -> Result<(), i32> {
    let new_size = allocation_size(size)?;
    if new_size <= file.buffer.len() {
        return Ok(());
    }
    file.buffer
        .try_reserve_exact(new_size - file.buffer.len())
        .map_err(|_| libc::ENOMEM)?;
    file.buffer.resize(new_size, 0);
    Ok(())
}

// Port of erts/emulator/drivers/common/ram_file_drv.c:274-283 and :302-310, OTP-29.1.1.
fn allocation_size(size: i64) -> Result<usize, i32> {
    if size < 0 {
        return Err(libc::EINVAL);
    }
    let rounded = size
        .checked_add(BUFFER_SLACK)
        .map(|n| n & !(BFILE_BLOCK - 1))
        .unwrap_or(i64::from(i32::MAX));
    usize::try_from(rounded).map_err(|_| libc::ENOMEM)
}

// Port of erts/emulator/drivers/common/ram_file_drv.c:275-287 and :312-316, OTP-29.1.1.
fn zeroed(size: usize) -> Result<Vec<u8>, i32> {
    let mut buffer = Vec::new();
    buffer.try_reserve_exact(size).map_err(|_| libc::ENOMEM)?;
    buffer.resize(size, 0);
    Ok(buffer)
}

// Port of erts/emulator/drivers/common/ram_file_drv.c:320-343 (ram_file_write), OTP-29.1.1.
fn write(file: &mut RamFile, data: &[u8], location: Option<i64>) -> Result<usize, i32> {
    if file.flags & RAM_FILE_MODE_WRITE == 0 {
        return Err(libc::EBADF);
    }
    let current = location.unwrap_or(file.position);
    let length = i64::try_from(data.len()).map_err(|_| libc::EINVAL)?;
    if current < 0 || length < 0 {
        return Err(libc::EINVAL);
    }
    let end = current.checked_add(length).ok_or(libc::EINVAL)?;
    if end < 0 {
        return Err(libc::EINVAL);
    }
    if end > file.buffer.len() as i64 {
        expand(file, end)?;
    }
    let start = usize::try_from(current).map_err(|_| libc::EINVAL)?;
    let finish = usize::try_from(end).map_err(|_| libc::EINVAL)?;
    file.buffer
        .get_mut(start..finish)
        .ok_or(libc::EINVAL)?
        .copy_from_slice(data);
    if end > file.end {
        file.end = end;
    }
    if location.is_none() {
        file.position = end;
    }
    Ok(data.len())
}

// Port of erts/emulator/drivers/common/ram_file_drv.c:344-372 (ram_file_read), OTP-29.1.1.
fn read(file: &mut RamFile, length: i64, location: Option<i64>) -> Result<Vec<u8>, i32> {
    if file.flags & RAM_FILE_MODE_READ == 0 {
        return Err(libc::EBADF);
    }
    let current = location.unwrap_or(file.position);
    if current < 0 || length < 0 {
        return Err(libc::EINVAL);
    }
    let count = if current < file.end {
        length.min(file.end - current)
    } else {
        0
    };
    let start = usize::try_from(current).map_err(|_| libc::EINVAL)?;
    let end = usize::try_from(current + count).map_err(|_| libc::EINVAL)?;
    let mut data = zeroed(usize::try_from(count).map_err(|_| libc::ENOMEM)?)?;
    if count != 0 {
        data.copy_from_slice(file.buffer.get(start..end).ok_or(libc::EINVAL)?);
    }
    if location.is_none() {
        file.position = current + count;
    }
    Ok(data)
}

// Port of erts/emulator/drivers/common/ram_file_drv.c:374-391 (ram_file_seek), OTP-29.1.1.
fn seek(file: &mut RamFile, offset: i64, origin: i32) -> Result<i64, i32> {
    if file.flags == 0 {
        return Err(libc::EBADF);
    }
    let position = match origin {
        RAM_FILE_SEEK_SET => offset,
        RAM_FILE_SEEK_CUR => file.position.checked_add(offset).ok_or(libc::EINVAL)?,
        RAM_FILE_SEEK_END => file.end.checked_add(offset).ok_or(libc::EINVAL)?,
        _ => return Err(libc::EINVAL),
    };
    if position < 0 {
        return Err(libc::EINVAL);
    }
    file.position = position;
    Ok(position)
}

// Port of erts/emulator/drivers/common/ram_file_drv.c:220-229 (reply), OTP-29.1.1.
fn ok_reply() -> Vec<u8> {
    vec![RAM_FILE_RESP_OK]
}

// Port of erts/emulator/drivers/common/ram_file_drv.c:208-218 (error_reply), OTP-29.1.1.
fn error_reply(error: i32) -> Vec<u8> {
    let name = crate::inet_drv::errno_name(error);
    let mut reply = Vec::with_capacity(name.len() + 1);
    reply.push(RAM_FILE_RESP_ERROR);
    reply.extend_from_slice(name.as_bytes());
    reply
}

// Port of erts/emulator/drivers/common/ram_file_drv.c:232-247 (numeric_reply), OTP-29.1.1.
fn number_reply(value: i64) -> Vec<u8> {
    let mut reply = Vec::with_capacity(5);
    reply.push(RAM_FILE_RESP_NUMBER);
    reply.extend_from_slice(&(value as i32).to_be_bytes());
    reply
}

// Port of erts/emulator/drivers/common/ram_file_drv.c:466-469, :479-482 and :506-509.
fn data_reply(data: &[u8]) -> Vec<u8> {
    let mut reply = Vec::with_capacity(5 + data.len());
    reply.push(RAM_FILE_RESP_DATA);
    reply.extend_from_slice(&(data.len() as i32).to_be_bytes());
    reply.extend_from_slice(data);
    reply
}
