//! Простейший интерфейс аппаратного сейфа на базе PUF (DeviceBindingKey).
//!
//! На реальном устройстве этот модуль должен быть проброшен к secure element/PUF.
//! Здесь реализован слой, который шифрует и аутентифицирует секреты перед записью
//! в выделенный участок Flash. Даже при полном дампе Flash значения секретов
//! остаются бесполезными без доступа к Device Binding (PUF).
use core::ptr;

use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::Zeroize;

use crate::error::IdentityError;
use crate::platform::device::DeviceBindingKey;
use crate::platform::rom;

include!(concat!(env!("OUT_DIR"), "/flash_layout.rs"));

type HmacSha256 = Hmac<Sha256>;

const FLASH_BASE: usize = 0x1000_0000;
const FLASH_SECTOR_SIZE: usize = 4096;
const FLASH_ERASE_CMD: u8 = 0x20;
const SECURE_OFFSET: usize = FLASH_SECURE_VAULT_OFFSET_CFG;
const SECURE_SIZE: usize = FLASH_SECURE_VAULT_SECTORS_CFG * FLASH_SECTOR_SIZE;
const MAGIC: [u8; 4] = *b"SVLT";
const VERSION: u8 = 1;
const SLOT_HEADER_SIZE: usize = 8; // magic + version/slot/reserved
const SLOT_CIPHERTEXT: usize = 32;
const SLOT_MAC: usize = 32;
const SLOT_DATA_SIZE: usize = SLOT_HEADER_SIZE + SLOT_CIPHERTEXT + SLOT_MAC;
const SLOT_STRIDE: usize = FLASH_SECTOR_SIZE;
const PROGRAM_SIZE: usize = FLASH_PAGE_SIZE;
const MAX_SLOTS: usize = FLASH_SECURE_VAULT_SECTORS_CFG;

/// Слоты защищённого хранилища.
#[derive(Clone, Copy)]
pub enum VaultSlot {
    IdentitySecret = 0,
    LittleFsMasterKey = 1,
    SyncNonceCounter = 2,
}

impl VaultSlot {
    fn index(self) -> usize {
        self as usize
    }
}

pub struct SecureVault;

impl SecureVault {
    pub const fn new() -> Self {
        SecureVault
    }

    /// Сохраняет secret key пользователя в hardware vault.
    pub fn store_identity_secret(&self, secret: &[u8; 32]) -> Result<(), IdentityError> {
        self.write_slot(VaultSlot::IdentitySecret, secret)
    }

    /// Загружает secret key из hardware vault.
    pub fn load_identity_secret(&self) -> Result<[u8; 32], IdentityError> {
        self.read_slot(VaultSlot::IdentitySecret)
    }

    pub fn store_application_secret(
        &self,
        slot: VaultSlot,
        secret: &[u8; 32],
    ) -> Result<(), IdentityError> {
        self.write_slot(slot, secret)
    }

    pub fn load_application_secret(&self, slot: VaultSlot) -> Result<[u8; 32], IdentityError> {
        self.read_slot(slot)
    }

    fn write_slot(&self, slot: VaultSlot, secret: &[u8; 32]) -> Result<(), IdentityError> {
        let slot_index = slot.index();
        if slot_index >= MAX_SLOTS {
            return Err(IdentityError::StorageUnavailable);
        }
        let offset = SECURE_OFFSET + slot_index * SLOT_STRIDE;
        let (cipher, mac) = self.wrap_secret(slot_index as u8, secret)?;

        let mut record = [0xFFu8; PROGRAM_SIZE];
        record[..4].copy_from_slice(&MAGIC);
        record[4] = VERSION;
        record[5] = slot_index as u8;
        record[6] = 0;
        record[7] = 0;
        record[SLOT_HEADER_SIZE..SLOT_HEADER_SIZE + SLOT_CIPHERTEXT].copy_from_slice(&cipher);
        record[SLOT_HEADER_SIZE + SLOT_CIPHERTEXT..SLOT_DATA_SIZE].copy_from_slice(&mac);

        unsafe {
            rom::connect_internal_flash();
            rom::flash_exit_xip();
            rom::flash_range_erase(
                offset as u32,
                FLASH_SECTOR_SIZE,
                FLASH_SECTOR_SIZE as u32,
                FLASH_ERASE_CMD,
            );
            rom::flash_range_program(offset as u32, record.as_ptr(), PROGRAM_SIZE);
            rom::flash_flush_cache();
            rom::flash_enter_cmd_xip();
            rom::connect_internal_flash();
            rom::flash_flush_cache();
        }

        let mut verify = [0u8; PROGRAM_SIZE];
        unsafe {
            ptr::copy_nonoverlapping(
                (FLASH_BASE + offset) as *const u8,
                verify.as_mut_ptr(),
                PROGRAM_SIZE,
            );
        }
        if verify != record {
            record.zeroize();
            verify.zeroize();
            return Err(IdentityError::FlashWriteFailed);
        }
        record.zeroize();
        verify.zeroize();
        Ok(())
    }

    fn read_slot(&self, slot: VaultSlot) -> Result<[u8; 32], IdentityError> {
        let slot_index = slot.index();
        if slot_index >= MAX_SLOTS {
            return Err(IdentityError::StorageUnavailable);
        }
        let offset = SECURE_OFFSET + slot_index * SLOT_STRIDE;
        let mut record = [0u8; PROGRAM_SIZE];
        unsafe {
            ptr::copy_nonoverlapping(
                (FLASH_BASE + offset) as *const u8,
                record.as_mut_ptr(),
                PROGRAM_SIZE,
            );
        }

        if record[..4] != MAGIC || record[4] != VERSION || record[5] != slot_index as u8 {
            record.zeroize();
            return Err(IdentityError::StorageNotFound);
        }

        let mut cipher = [0u8; SLOT_CIPHERTEXT];
        cipher.copy_from_slice(&record[SLOT_HEADER_SIZE..SLOT_HEADER_SIZE + SLOT_CIPHERTEXT]);
        let mut mac = [0u8; SLOT_MAC];
        mac.copy_from_slice(&record[SLOT_HEADER_SIZE + SLOT_CIPHERTEXT..SLOT_DATA_SIZE]);
        record.zeroize();

        let mut plain = self.unwrap_secret(slot_index as u8, &cipher, &mac)?;
        cipher.zeroize();
        mac.zeroize();
        Ok(plain)
    }

    fn wrap_secret(
        &self,
        slot: u8,
        secret: &[u8; 32],
    ) -> Result<([u8; 32], [u8; 32]), IdentityError> {
        let binding = DeviceBindingKey::new()?;
        let mut keystream = HmacSha256::new_from_slice(binding.as_bytes())?;
        keystream.update(b"zk-secure-vault-mask");
        keystream.update(&[slot]);
        let stream = keystream.finalize().into_bytes();
        let mut cipher = [0u8; 32];
        for i in 0..32 {
            cipher[i] = secret[i] ^ stream[i];
        }
        let mut mac = HmacSha256::new_from_slice(binding.as_bytes())?;
        mac.update(b"zk-secure-vault-mac");
        mac.update(&[slot]);
        mac.update(&cipher);
        let mac_bytes = mac.finalize().into_bytes();
        let mut mac_arr = [0u8; 32];
        mac_arr.copy_from_slice(&mac_bytes);
        Ok((cipher, mac_arr))
    }

    fn unwrap_secret(
        &self,
        slot: u8,
        cipher: &[u8; 32],
        mac_expected: &[u8; 32],
    ) -> Result<[u8; 32], IdentityError> {
        let binding = DeviceBindingKey::new()?;
        let mut mac = HmacSha256::new_from_slice(binding.as_bytes())?;
        mac.update(b"zk-secure-vault-mac");
        mac.update(&[slot]);
        mac.update(cipher);
        let mac_bytes = mac.finalize().into_bytes();
        if mac_bytes.as_slice() != mac_expected {
            return Err(IdentityError::StorageCorrupted);
        }

        let mut keystream = HmacSha256::new_from_slice(binding.as_bytes())?;
        keystream.update(b"zk-secure-vault-mask");
        keystream.update(&[slot]);
        let stream = keystream.finalize().into_bytes();
        let mut plain = [0u8; 32];
        for i in 0..32 {
            plain[i] = cipher[i] ^ stream[i];
        }
        Ok(plain)
    }
}
