use core::cmp::min;
use core::ptr;

use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::error::IdentityError;
use crate::identity::hkdf::derive_storage_keys;
use crate::identity::types::{DeviceId, IdentityState, RootKey, UserSecret};

type HmacSha256 = Hmac<Sha256>;

pub struct FlashStorage;

const FLASH_BASE: usize = 0x1000_0000;
const FLASH_TOTAL_SIZE: usize = 2 * 1024 * 1024;
const FLASH_SECTOR_SIZE: usize = 4096;
const FLASH_PAGE_SIZE: usize = 256;
const FLASH_STORAGE_OFFSET: usize = FLASH_TOTAL_SIZE - FLASH_SECTOR_SIZE;
const FLASH_ERASE_CMD: u8 = 0x20;

const MAGIC: [u8; 4] = *b"ZKGS";
const FORMAT_VERSION: u8 = 1;

const HEADER_SIZE: usize = 32;
const PAYLOAD_SIZE: usize = 32;
const MAC_SIZE: usize = 32;
const RECORD_DATA_SIZE: usize = HEADER_SIZE + PAYLOAD_SIZE;
const RECORD_TOTAL_SIZE: usize = RECORD_DATA_SIZE + MAC_SIZE;

#[derive(Clone, Copy)]
struct StoredHeader {
    device_id: DeviceId,
    counter: u32,
}

impl FlashStorage {
    pub const fn new() -> Self {
        FlashStorage
    }

    pub fn seal(&self, state: &IdentityState) -> Result<(), IdentityError> {
        let existing_counter = self.load_header()?.map(|h| h.counter).unwrap_or(0);
        let counter = existing_counter.wrapping_add(1).max(1);

        let (mut enc_key, mut mac_key) =
            derive_storage_keys(&state.root_key, &state.device_id)?;

        let mut ciphertext = [0u8; PAYLOAD_SIZE];
        ciphertext.copy_from_slice(&state.sk_user.0);
        Self::apply_keystream(&enc_key, &state.device_id, counter, &mut ciphertext)?;

        let mut header_bytes = [0u8; HEADER_SIZE];
        Self::write_header(&mut header_bytes, counter, &state.device_id);

        let mut record = [0u8; RECORD_TOTAL_SIZE];
        record[..HEADER_SIZE].copy_from_slice(&header_bytes);
        record[HEADER_SIZE..HEADER_SIZE + PAYLOAD_SIZE].copy_from_slice(&ciphertext);

        let mac = Self::compute_mac(&mac_key, &header_bytes, &ciphertext)?;
        record[RECORD_DATA_SIZE..].copy_from_slice(&mac);

        let mut page = [0xFFu8; FLASH_PAGE_SIZE];
        page[..RECORD_TOTAL_SIZE].copy_from_slice(&record);

        self.program_sector(&page)?;

        let mut verify = [0u8; RECORD_TOTAL_SIZE];
        self.read_flash(0, &mut verify);
        if !Self::timing_safe_eq(&verify, &record) {
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

        Ok(())
    }

    pub fn unseal(&self, root_key: &RootKey) -> Result<IdentityState, IdentityError> {
        let mut header_bytes = [0u8; HEADER_SIZE];
        self.read_flash(0, &mut header_bytes);
        if Self::is_erased(&header_bytes) {
            return Err(IdentityError::StorageNotFound);
        }

        let header = Self::parse_header(&header_bytes)?;

        let mut payload = [0u8; PAYLOAD_SIZE];
        self.read_flash(HEADER_SIZE, &mut payload);
        let mut stored_mac = [0u8; MAC_SIZE];
        self.read_flash(RECORD_DATA_SIZE, &mut stored_mac);

        let (mut enc_key, mut mac_key) = derive_storage_keys(root_key, &header.device_id)?;
        let mut expected_mac = Self::compute_mac(&mac_key, &header_bytes, &payload)?;
        if !Self::timing_safe_eq(&stored_mac, &expected_mac) {
            enc_key.fill(0);
            mac_key.fill(0);
            payload.fill(0);
            stored_mac.fill(0);
            expected_mac.fill(0);
            header_bytes.fill(0);
            return Err(IdentityError::StorageMacMismatch);
        }

        Self::apply_keystream(&enc_key, &header.device_id, header.counter, &mut payload)?;

        let mut root_bytes = [0u8; 32];
        root_bytes.copy_from_slice(&root_key.0);
        let mut sk = [0u8; 32];
        sk.copy_from_slice(&payload);

        enc_key.fill(0);
        mac_key.fill(0);
        payload.fill(0);
        expected_mac.fill(0);
        stored_mac.fill(0);
        header_bytes.fill(0);

        Ok(IdentityState {
            root_key: RootKey(root_bytes),
            device_id: header.device_id,
            sk_user: UserSecret(sk),
        })
    }

    fn load_header(&self) -> Result<Option<StoredHeader>, IdentityError> {
        let mut header_bytes = [0u8; HEADER_SIZE];
        self.read_flash(0, &mut header_bytes);
        if Self::is_erased(&header_bytes) {
            return Ok(None);
        }
        Self::parse_header(&header_bytes).map(Some)
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
        let mut device = [0u8; 16];
        device.copy_from_slice(&bytes[16..32]);

        Ok(StoredHeader {
            counter,
            device_id: DeviceId(device),
        })
    }

    fn write_header(buf: &mut [u8; HEADER_SIZE], counter: u32, device: &DeviceId) {
        buf[..4].copy_from_slice(&MAGIC);
        buf[4] = FORMAT_VERSION;
        buf[5] = 0;
        buf[6..8].copy_from_slice(&(PAYLOAD_SIZE as u16).to_le_bytes());
        buf[8..12].copy_from_slice(&counter.to_le_bytes());
        buf[12..16].copy_from_slice(&0u32.to_le_bytes());
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
            let mut prf =
                HmacSha256::new_from_slice(enc_key).map_err(|_| IdentityError::DerivationFailed)?;
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
        let mut mac =
            HmacSha256::new_from_slice(mac_key).map_err(|_| IdentityError::DerivationFailed)?;
        mac.update(header);
        mac.update(payload);
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

    fn read_flash(&self, offset: usize, buf: &mut [u8]) {
        debug_assert!(offset + buf.len() <= FLASH_SECTOR_SIZE);
        let addr = FLASH_BASE + FLASH_STORAGE_OFFSET + offset;
        unsafe {
            ptr::copy_nonoverlapping(addr as *const u8, buf.as_mut_ptr(), buf.len());
        }
    }

    fn program_sector(&self, page: &[u8; FLASH_PAGE_SIZE]) -> Result<(), IdentityError> {
        unsafe {
            rom::connect_internal_flash();
            rom::flash_exit_xip();
            rom::flash_range_erase(
                FLASH_STORAGE_OFFSET as u32,
                FLASH_SECTOR_SIZE,
                FLASH_SECTOR_SIZE as u32,
                FLASH_ERASE_CMD,
            );
            rom::flash_range_program(FLASH_STORAGE_OFFSET as u32, page.as_ptr(), FLASH_PAGE_SIZE);
            rom::flash_flush_cache();
            rom::flash_enter_cmd_xip();
            rom::connect_internal_flash();
            rom::flash_flush_cache();
        }
        Ok(())
    }
}

mod rom {
    use core::mem;
    use core::ptr;

    const FUNC_TABLE: *const u16 = 0x0000_0014 as *const u16;
    const ROM_TABLE_LOOKUP_PTR: *const u16 = 0x0000_0018 as *const u16;

    pub unsafe fn flash_exit_xip() {
        call_void(*b"EX");
    }

    pub unsafe fn flash_enter_cmd_xip() {
        call_void(*b"CX");
    }

    pub unsafe fn flash_flush_cache() {
        call_void(*b"FC");
    }

    pub unsafe fn connect_internal_flash() {
        call_void(*b"IF");
    }

    pub unsafe fn flash_range_erase(
        addr: u32,
        count: usize,
        block_size: u32,
        block_cmd: u8,
    ) {
        let func = lookup(*b"RE");
        let erase: extern "C" fn(u32, usize, u32, u8) =
            mem::transmute(func);
        erase(addr, count, block_size, block_cmd);
    }

    pub unsafe fn flash_range_program(addr: u32, data: *const u8, count: usize) {
        let func = lookup(*b"RP");
        let program: extern "C" fn(u32, *const u8, usize) =
            mem::transmute(func);
        program(addr, data, count);
    }

    fn lookup(tag: [u8; 2]) -> *const u32 {
        unsafe {
            let table = rom_hword_as_ptr(FUNC_TABLE);
            let lookup_ptr = rom_hword_as_ptr(ROM_TABLE_LOOKUP_PTR);
            let lookup_fn: extern "C" fn(*const u16, u32) -> *const u32 =
                mem::transmute(lookup_ptr);
            lookup_fn(table as *const u16, u16::from_le_bytes(tag) as u32)
        }
    }

    unsafe fn call_void(tag: [u8; 2]) {
        let func = lookup(tag);
        let f: extern "C" fn() = mem::transmute(func);
        f();
    }

    unsafe fn rom_hword_as_ptr(addr: *const u16) -> *const u32 {
        let value = ptr::read(addr);
        value as *const u32
    }
}
