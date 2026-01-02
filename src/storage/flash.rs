//! Надёжное хранение состояния личности во Flash с wear-leveling.
//!
//! # Пример
//! ```no_run
//! use zk_gatekeeper::storage::flash::FlashStorage;
//! use zk_gatekeeper::identity::types::{DeviceId, IdentityState, RootKey};
//!
//! let state = IdentityState::from_root(RootKey([0x11; 32]), DeviceId([1; 16])).unwrap();
//! let flash = FlashStorage::new();
//! flash.seal(&state).unwrap();
//! let restored = flash.unseal(&state.root_key).unwrap();
//! assert!(restored.identifier().matches(state.public_key().as_bytes()));
//! ```
use core::cmp::min;
use core::ptr;

use hmac::{Hmac, Mac};
use log::{debug, info, warn};
use sha2::Sha256;
use subtle::ConstantTimeEq;

use crate::error::IdentityError;
use crate::identity::hkdf::derive_storage_keys;
use crate::identity::keys;
use crate::identity::types::{DeviceId, IdentityState, RootKey, UserPublicKey, UserSecret};
use crate::platform::device::DeviceBindingKey;
use crate::platform::rom;
use crate::platform::secure_boot::FirmwareGuard;
use crate::platform::secure_vault::SecureVault;
include!(concat!(env!("OUT_DIR"), "/flash_layout.rs"));

type HmacSha256 = Hmac<Sha256>;

/// Минимальный драйвер Flash с привязкой к конкретному устройству.
pub struct FlashStorage;

const FLASH_BASE: usize = 0x1000_0000;
const FLASH_SECTOR_SIZE: usize = 4096;
const FLASH_PAGE_SIZE: usize = 256;
const FLASH_STORAGE_SECTORS: usize = FLASH_STORAGE_SECTORS_CFG;
const FLASH_STORAGE_OFFSET: usize = FLASH_STORAGE_OFFSET_CFG;
const FLASH_STORAGE_SIZE: usize = FLASH_STORAGE_SECTORS * FLASH_SECTOR_SIZE;
const STORAGE_SLOT_COUNT: usize = FLASH_STORAGE_SECTORS;
const SLOT_SIZE: usize = FLASH_SECTOR_SIZE;
const FLASH_ERASE_CMD: u8 = 0x20;

const MAGIC: [u8; 4] = *b"ZKGS";
const FORMAT_VERSION: u8 = 1;

const HEADER_SIZE: usize = 32;
const SECRET_TAG_SIZE: usize = 32;
const PK_SIZE: usize = 32;
const PAYLOAD_SIZE: usize = SECRET_TAG_SIZE + PK_SIZE;
const MAC_SIZE: usize = 32;
const RECORD_DATA_SIZE: usize = HEADER_SIZE + PAYLOAD_SIZE;
const RECORD_TOTAL_SIZE: usize = RECORD_DATA_SIZE + MAC_SIZE;

#[derive(Clone, Copy)]
struct StoredHeader {
    device_id: DeviceId,
    counter: u32,
    epoch: u32,
}

struct SlotRecord {
    header: StoredHeader,
    header_bytes: [u8; HEADER_SIZE],
    slot: usize,
}

impl FlashStorage {
    /// Создаёт новый драйвер Flash.
    pub const fn new() -> Self {
        FlashStorage
    }

    /// Восстанавливает состояние с проверкой secure boot.
    pub fn unseal_with_guard(
        &self,
        root_key: &RootKey,
        guard: &FirmwareGuard,
    ) -> Result<IdentityState, IdentityError> {
        guard.verify()?;
        self.unseal(root_key)
    }

    /// Сохраняет состояние в зашифрованном виде.
    pub fn seal(&self, state: &IdentityState) -> Result<(), IdentityError> {
        let latest = self.latest_record()?;
        let existing_counter = latest.as_ref().map(|r| r.header.counter).unwrap_or(0);
        let existing_epoch = latest.as_ref().map(|r| r.header.epoch).unwrap_or(0);
        let (epoch, counter) = Self::advance_counter(existing_epoch, existing_counter)?;
        let target_slot = latest
            .as_ref()
            .map(|r| (r.slot + 1) % STORAGE_SLOT_COUNT)
            .unwrap_or(0);
        info!(
            "Flash seal start: slot={} epoch={} counter={} device={:x?}",
            target_slot,
            epoch,
            counter,
            state.device_id().0
        );

        let (mut enc_key, mut mac_key) = derive_storage_keys(&state.root_key, &state.device_id)?;
        let binding = DeviceBindingKey::new()?;
        binding.mix_into(&mut enc_key, &mut mac_key);
        drop(binding);

        let vault = SecureVault::new();
        vault.store_identity_secret(&state.sk_user.0)?;
        let mut secret_tag = Self::compute_secret_tag(&mac_key, &state.sk_user.0)?;

        let mut ciphertext = [0u8; PAYLOAD_SIZE];
        ciphertext[..SECRET_TAG_SIZE].copy_from_slice(&secret_tag);
        let pk_bytes = state.public_key().into_bytes();
        ciphertext[SECRET_TAG_SIZE..PAYLOAD_SIZE].copy_from_slice(&pk_bytes);
        secret_tag.zeroize();
        Self::apply_keystream(&enc_key, &state.device_id, counter, &mut ciphertext)?;

        let mut header_bytes = [0u8; HEADER_SIZE];
        Self::write_header(&mut header_bytes, epoch, counter, &state.device_id);

        let mut record = [0u8; RECORD_TOTAL_SIZE];
        record[..HEADER_SIZE].copy_from_slice(&header_bytes);
        record[HEADER_SIZE..HEADER_SIZE + PAYLOAD_SIZE].copy_from_slice(&ciphertext);

        let mac = Self::compute_mac(&mac_key, &header_bytes, &ciphertext)?;
        record[RECORD_DATA_SIZE..].copy_from_slice(&mac);

        let mut page = [0xFFu8; FLASH_PAGE_SIZE];
        page[..RECORD_TOTAL_SIZE].copy_from_slice(&record);

        self.program_slot(target_slot, &page)?;

        let mut verify = [0u8; RECORD_TOTAL_SIZE];
        self.read_slot(target_slot, 0, &mut verify);
        if !Self::timing_safe_eq(&verify, &record) {
            warn!("Flash seal verification mismatch in slot {}", target_slot);
            ciphertext.fill(0);
            enc_key.fill(0);
            mac_key.fill(0);
            header_bytes.fill(0);
            record.fill(0);
            page.fill(0);
            verify.fill(0);
            return Err(IdentityError::FlashWriteFailed);
        }

        ciphertext.fill(0);
        enc_key.fill(0);
        mac_key.fill(0);
        header_bytes.fill(0);
        record.fill(0);
        page.fill(0);
        verify.fill(0);
        debug!("Flash seal complete for slot {}", target_slot);

        Ok(())
    }

    /// Загружает последнее валидное состояние.
    pub fn unseal(&self, root_key: &RootKey) -> Result<IdentityState, IdentityError> {
        let record = self
            .latest_record()?
            .ok_or(IdentityError::StorageNotFound)?;
        let header = record.header;
        let mut header_bytes = record.header_bytes;
        info!(
            "Flash unseal: slot={} epoch={} counter={}",
            record.slot, header.epoch, header.counter
        );

        let mut payload = [0u8; PAYLOAD_SIZE];
        self.read_slot(record.slot, HEADER_SIZE, &mut payload);
        let mut stored_mac = [0u8; MAC_SIZE];
        self.read_slot(record.slot, RECORD_DATA_SIZE, &mut stored_mac);

        let (mut enc_key, mut mac_key) = derive_storage_keys(root_key, &header.device_id)?;
        let binding = DeviceBindingKey::new()?;
        binding.mix_into(&mut enc_key, &mut mac_key);
        drop(binding);
        let mut expected_mac = Self::compute_mac(&mac_key, &header_bytes, &payload)?;
        if !Self::timing_safe_eq(&stored_mac, &expected_mac) {
            warn!(
                "Flash MAC mismatch slot={} counter={}",
                record.slot, header.counter
            );
            enc_key.fill(0);
            mac_key.fill(0);
            payload.fill(0);
            stored_mac.fill(0);
            expected_mac.fill(0);
            header_bytes.fill(0);
            return Err(IdentityError::StorageMacMismatch);
        }

        Self::apply_keystream(&enc_key, &header.device_id, header.counter, &mut payload)?;

        let mut secret_tag = [0u8; SECRET_TAG_SIZE];
        secret_tag.copy_from_slice(&payload[..SECRET_TAG_SIZE]);
        let mut pk_bytes = [0u8; PK_SIZE];
        pk_bytes.copy_from_slice(&payload[SECRET_TAG_SIZE..PAYLOAD_SIZE]);

        let vault = SecureVault::new();
        let mut secret_bytes = vault.load_identity_secret()?;

        let mut derived_tag = Self::compute_secret_tag(&mac_key, &secret_bytes)?;
        if !Self::timing_safe_eq(&secret_tag, &derived_tag) {
            enc_key.fill(0);
            mac_key.fill(0);
            payload.fill(0);
            expected_mac.fill(0);
            stored_mac.fill(0);
            header_bytes.fill(0);
            derived_tag.zeroize();
            secret_tag.zeroize();
            pk_bytes.fill(0);
            secret_bytes.fill(0);
            return Err(IdentityError::StorageCorrupted);
        }
        derived_tag.zeroize();
        secret_tag.zeroize();

        let derived_pk = keys::public_key_from_secret(&secret_bytes);
        if derived_pk.ct_eq(&pk_bytes).unwrap_u8() != 1 {
            enc_key.fill(0);
            mac_key.fill(0);
            payload.fill(0);
            expected_mac.fill(0);
            stored_mac.fill(0);
            header_bytes.fill(0);
            secret_bytes.fill(0);
            pk_bytes.fill(0);
            return Err(IdentityError::StorageCorrupted);
        }

        let mut root_bytes = [0u8; 32];
        root_bytes.copy_from_slice(&root_key.0);

        enc_key.fill(0);
        mac_key.fill(0);
        payload.fill(0);
        expected_mac.fill(0);
        stored_mac.fill(0);
        header_bytes.fill(0);

        pk_bytes.fill(0);

        Ok(IdentityState {
            root_key: RootKey(root_bytes),
            device_id: header.device_id,
            sk_user: UserSecret(secret_bytes),
        })
    }

    fn latest_record(&self) -> Result<Option<SlotRecord>, IdentityError> {
        let mut best: Option<SlotRecord> = None;
        let mut last_error: Option<IdentityError> = None;

        for slot in 0..STORAGE_SLOT_COUNT {
            let mut header_bytes = [0u8; HEADER_SIZE];
            self.read_slot(slot, 0, &mut header_bytes);
            if Self::is_erased(&header_bytes) {
                continue;
            }

            match Self::parse_header(&header_bytes) {
                Ok(header) => {
                    let should_replace = best
                        .as_ref()
                        .map(|record| {
                            header.epoch > record.header.epoch
                                || (header.epoch == record.header.epoch
                                    && header.counter > record.header.counter)
                        })
                        .unwrap_or(true);
                    if should_replace {
                        best = Some(SlotRecord {
                            header,
                            header_bytes,
                            slot,
                        });
                    }
                }
                Err(err) => {
                    warn!("Invalid flash header in slot {}: {:?}", slot, err);
                    last_error = Some(err);
                }
            }
        }

        if let Some(record) = best {
            Ok(Some(record))
        } else if let Some(err) = last_error {
            Err(err)
        } else {
            Ok(None)
        }
    }

    fn parse_header(bytes: &[u8]) -> Result<StoredHeader, IdentityError> {
        if !bytes.starts_with(&MAGIC) {
            return Err(IdentityError::StorageCorrupted);
        }

        let version = bytes[4];
        if version != FORMAT_VERSION {
            return Err(IdentityError::StorageVersionMismatch);
        }

        let payload_len = u16::from_le_bytes([bytes[6], bytes[7]]) as usize;
        if payload_len != PAYLOAD_SIZE {
            return Err(IdentityError::StorageCorrupted);
        }

        let counter = u32::from_le_bytes(bytes[8..12].try_into().unwrap());
        let epoch = u32::from_le_bytes(bytes[12..16].try_into().unwrap());
        let mut device = [0u8; 16];
        device.copy_from_slice(&bytes[16..32]);

        Ok(StoredHeader {
            counter,
            epoch,
            device_id: DeviceId(device),
        })
    }

    fn write_header(buf: &mut [u8; HEADER_SIZE], epoch: u32, counter: u32, device: &DeviceId) {
        buf[..4].copy_from_slice(&MAGIC);
        buf[4] = FORMAT_VERSION;
        buf[5] = 0;
        buf[6..8].copy_from_slice(&(PAYLOAD_SIZE as u16).to_le_bytes());
        buf[8..12].copy_from_slice(&counter.to_le_bytes());
        buf[12..16].copy_from_slice(&epoch.to_le_bytes());
        buf[16..32].copy_from_slice(&device.0);
    }

    fn apply_keystream(
        enc_key: &[u8; 32],
        device: &DeviceId,
        counter: u32,
        data: &mut [u8],
    ) -> Result<(), IdentityError> {
        let mut block = 0u32;
        let mut offset = 0usize;

        while offset < data.len() {
            let mut prf = HmacSha256::new_from_slice(enc_key)?;
            prf.update(&device.0);
            prf.update(&counter.to_le_bytes());
            prf.update(&block.to_le_bytes());

            let digest = prf.finalize().into_bytes();
            let mut stream = [0u8; 32];
            stream.copy_from_slice(&digest);

            let take = min(stream.len(), data.len() - offset);
            for i in 0..take {
                data[offset + i] ^= stream[i];
            }

            stream.fill(0);
            block = block.wrapping_add(1);
            offset += take;
        }

        Ok(())
    }

    fn compute_mac(
        mac_key: &[u8; 32],
        header: &[u8],
        payload: &[u8],
    ) -> Result<[u8; 32], IdentityError> {
        let mut mac = HmacSha256::new_from_slice(mac_key)?;
        mac.update(header);
        mac.update(payload);
        let digest = mac.finalize().into_bytes();
        let mut out = [0u8; 32];
        out.copy_from_slice(&digest);
        Ok(out)
    }

    fn compute_secret_tag(
        mac_key: &[u8; 32],
        secret: &[u8; 32],
    ) -> Result<[u8; 32], IdentityError> {
        let mut mac = HmacSha256::new_from_slice(mac_key)?;
        mac.update(b"zk-gatekeeper-secret-tag");
        mac.update(secret);
        let digest = mac.finalize().into_bytes();
        let mut out = [0u8; 32];
        out.copy_from_slice(&digest);
        Ok(out)
    }

    fn is_erased(buf: &[u8]) -> bool {
        buf.iter().all(|b| *b == 0xFF)
    }

    fn timing_safe_eq(a: &[u8], b: &[u8]) -> bool {
        if a.len() != b.len() {
            return false;
        }

        let mut diff = 0u8;
        for (x, y) in a.iter().zip(b.iter()) {
            diff |= x ^ y;
        }
        diff == 0
    }

    fn advance_counter(epoch: u32, counter: u32) -> Result<(u32, u32), IdentityError> {
        if counter == u32::MAX {
            let next_epoch = epoch
                .checked_add(1)
                .ok_or(IdentityError::StorageCorrupted)?;
            Ok((next_epoch, 1))
        } else {
            let next = counter + 1;
            let counter = if next == 0 { 1 } else { next };
            Ok((epoch, counter))
        }
    }

    fn read_slot(&self, slot: usize, offset: usize, buf: &mut [u8]) {
        debug_assert!(slot < STORAGE_SLOT_COUNT);
        debug_assert!(offset + buf.len() <= SLOT_SIZE);
        let addr = FLASH_BASE + Self::slot_offset(slot) + offset;
        unsafe {
            ptr::copy_nonoverlapping(addr as *const u8, buf.as_mut_ptr(), buf.len());
        }
    }

    fn program_slot(&self, slot: usize, page: &[u8; FLASH_PAGE_SIZE]) -> Result<(), IdentityError> {
        debug_assert!(slot < STORAGE_SLOT_COUNT);
        let offset = Self::slot_offset(slot);
        unsafe {
            rom::connect_internal_flash();
            rom::flash_exit_xip();
            rom::flash_range_erase(
                offset as u32,
                FLASH_SECTOR_SIZE,
                FLASH_SECTOR_SIZE as u32,
                FLASH_ERASE_CMD,
            );
            rom::flash_range_program(offset as u32, page.as_ptr(), FLASH_PAGE_SIZE);
            rom::flash_flush_cache();
            rom::flash_enter_cmd_xip();
            rom::connect_internal_flash();
            rom::flash_flush_cache();
        }
        Ok(())
    }

    const fn slot_offset(slot: usize) -> usize {
        FLASH_STORAGE_OFFSET + slot * SLOT_SIZE
    }
}
