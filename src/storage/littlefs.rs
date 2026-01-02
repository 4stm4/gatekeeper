//! LittleFS-драйвер поверх внутренней Flash RP2040.
use core::ptr;

use littlefs2::consts;
use littlefs2::driver::Storage as FsStorage;
use littlefs2::fs::Filesystem;
use littlefs2::io::{Error as FsError, Result as FsResult};

use crate::error::IdentityError;
use crate::platform::rom;
use crate::platform::secure_vault::{SecureVault, VaultSlot};

include!(concat!(env!("OUT_DIR"), "/flash_layout.rs"));

const FLASH_BASE: usize = 0x1000_0000;
const FLASH_SECTOR_SIZE: usize = 4096;
const FLASH_PAGE_SIZE: usize = 256;
const FLASH_ERASE_CMD: u8 = 0x20;
const FLASH_FS_BLOCKS: usize = FLASH_FS_BLOCKS_CFG;
const FLASH_FS_OFFSET: usize = FLASH_FS_OFFSET_CFG;
const FLASH_FS_SIZE: usize = FLASH_FS_BLOCKS * FLASH_SECTOR_SIZE;

/// Helper, который форматирует и монтирует LittleFS в зарезервированном разделе.
pub struct LittleFs {
    storage: FlashStorageDriver,
}

impl LittleFs {
    /// Создаёт новое файловое хранилище.
    pub const fn new() -> Self {
        Self {
            storage: FlashStorageDriver,
        }
    }

    /// Выполняет форматирование раздела.
    pub fn format(&mut self) -> Result<(), IdentityError> {
        Filesystem::format(&mut self.storage).map_err(map_fs_err)
    }

    /// Монтирует раздел и выполняет произвольную операцию в замыкании.
    pub fn mount<R>(
        &mut self,
        f: impl FnOnce(&Filesystem<'_, FlashStorageDriver>) -> FsResult<R>,
    ) -> Result<R, IdentityError> {
        Filesystem::mount_and_then(&mut self.storage, f).map_err(map_fs_err)
    }

    /// Предоставляет мутабельный доступ к драйверу хранения.
    pub fn storage(&mut self) -> &mut FlashStorageDriver {
        &mut self.storage
    }

    /// Сохраняет master-key файловой системы в защищённом хранилище.
    pub fn store_master_key(&self, key: &[u8; 32]) -> Result<(), IdentityError> {
        SecureVault::new().store_application_secret(VaultSlot::LittleFsMasterKey, key)
    }

    /// Загружает master-key из secure element.
    pub fn load_master_key(&self) -> Result<[u8; 32], IdentityError> {
        SecureVault::new().load_application_secret(VaultSlot::LittleFsMasterKey)
    }
}

fn map_fs_err(err: FsError) -> IdentityError {
    log::warn!("LittleFS error: {:?}", err.code());
    IdentityError::StorageError
}

/// Реализация LittleFS Storage поверх внутренней Flash RP2040.
pub struct FlashStorageDriver;

impl FlashStorageDriver {
    const fn flash_addr(offset: usize) -> *const u8 {
        (FLASH_BASE + FLASH_FS_OFFSET + offset) as *const u8
    }

    const fn flash_offset(offset: usize) -> usize {
        FLASH_FS_OFFSET + offset
    }

    fn check_bounds(offset: usize, len: usize) -> FsResult<()> {
        let end = offset.checked_add(len).ok_or(FsError::INVALID)?;
        if end > FLASH_FS_SIZE {
            Err(FsError::INVALID)
        } else {
            Ok(())
        }
    }
}

impl FsStorage for FlashStorageDriver {
    const READ_SIZE: usize = 16;
    const WRITE_SIZE: usize = FLASH_PAGE_SIZE;
    const BLOCK_SIZE: usize = FLASH_SECTOR_SIZE;
    const BLOCK_COUNT: usize = FLASH_FS_BLOCKS;
    type CACHE_SIZE = consts::U256;
    type LOOKAHEAD_SIZE = consts::U16;

    fn read(&mut self, off: usize, buf: &mut [u8]) -> FsResult<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        Self::check_bounds(off, buf.len())?;
        let addr = Self::flash_addr(off);
        unsafe {
            ptr::copy_nonoverlapping(addr, buf.as_mut_ptr(), buf.len());
        }
        Ok(buf.len())
    }

    fn write(&mut self, off: usize, data: &[u8]) -> FsResult<usize> {
        if data.is_empty() {
            return Ok(0);
        }
        Self::check_bounds(off, data.len())?;
        debug_assert_eq!(data.len() % FLASH_PAGE_SIZE, 0);
        unsafe {
            rom::connect_internal_flash();
            rom::flash_exit_xip();
            rom::flash_range_program(Self::flash_offset(off) as u32, data.as_ptr(), data.len());
            rom::flash_flush_cache();
            rom::flash_enter_cmd_xip();
            rom::connect_internal_flash();
            rom::flash_flush_cache();
        }
        Ok(data.len())
    }

    fn erase(&mut self, off: usize, len: usize) -> FsResult<usize> {
        if len == 0 {
            return Ok(0);
        }
        if len % FLASH_SECTOR_SIZE != 0 {
            return Err(FsError::INVALID);
        }
        Self::check_bounds(off, len)?;
        unsafe {
            rom::connect_internal_flash();
            rom::flash_exit_xip();
            rom::flash_range_erase(
                Self::flash_offset(off) as u32,
                len,
                FLASH_SECTOR_SIZE as u32,
                FLASH_ERASE_CMD,
            );
            rom::flash_flush_cache();
            rom::flash_enter_cmd_xip();
            rom::connect_internal_flash();
            rom::flash_flush_cache();
        }
        Ok(len)
    }
}
