use alloc::vec::Vec;
use core::convert::TryInto;

use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::error::IdentityError;
use crate::handshake::CapabilityFlags;
use crate::identity::types::IdentityIdentifier;
use crate::platform::secure_vault::{SecureVault, VaultSlot};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

type HmacSha256 = Hmac<Sha256>;

const RECORD_VERSION: u8 = 1;

#[derive(Clone, Copy)]
pub struct RatchetStateRow {
    pub identity: IdentityIdentifier,
    pub root_key: [u8; 32],
    pub send_chain: [u8; 32],
    pub recv_chain: [u8; 32],
    pub send_count: u32,
    pub recv_count: u32,
}

#[derive(Clone, Copy)]
pub struct ContactMetadata {
    pub identity: IdentityIdentifier,
    pub capabilities: CapabilityFlags,
    pub last_seen_epoch: u64,
    pub trust_level: u8,
}

#[derive(Clone)]
pub struct SecureStore {
    ratchets: Vec<RatchetStateRow>,
    contacts: Vec<ContactMetadata>,
    wal_shadow: Vec<WalRecord>,
    wal_dirty: bool,
    cipher: SecureCipher,
    counter: FlashCounter,
    wal_nonce: u64,
}

pub struct WalTransaction {
    records: Vec<WalOp>,
}

#[derive(Clone, Copy)]
enum WalOp {
    UpsertRatchet(RatchetStateRow),
    UpsertContact(ContactMetadata),
    DeleteContact(IdentityIdentifier),
}

#[derive(Clone)]
enum WalRecord {
    UpsertRatchet { nonce: u64, ciphertext: [u8; WalRecord::RATCHET_SIZE] },
    UpsertContact(ContactMetadata),
    DeleteContact(IdentityIdentifier),
}

impl WalRecord {
    const RATCHET_SIZE: usize = core::mem::size_of::<RatchetStateRow>();

    fn encrypt_ratchet(
        row: &RatchetStateRow,
        nonce: u64,
        cipher: &SecureCipher,
    ) -> Self {
        let mut buf = Self::encode_ratchet_bytes(row);
        cipher.xor_keystream(nonce, &mut buf);
        Self::UpsertRatchet { nonce, ciphertext: buf }
    }

    fn decrypt_ratchet(&self, cipher: &SecureCipher) -> Option<RatchetStateRow> {
        match self {
            WalRecord::UpsertRatchet { nonce, ciphertext } => {
                let mut buf = *ciphertext;
                cipher.xor_keystream(*nonce, &mut buf);
                let row = Self::decode_ratchet_bytes(&buf);
                buf.zeroize();
                Some(row)
            }
            _ => None,
        }
    }

    fn encode_ratchet_bytes(row: &RatchetStateRow) -> [u8; Self::RATCHET_SIZE] {
        let mut buf = [0u8; Self::RATCHET_SIZE];
        let mut offset = 0;
        buf[offset..offset + 32].copy_from_slice(row.identity.as_bytes());
        offset += 32;
        buf[offset..offset + 32].copy_from_slice(&row.root_key);
        offset += 32;
        buf[offset..offset + 32].copy_from_slice(&row.send_chain);
        offset += 32;
        buf[offset..offset + 32].copy_from_slice(&row.recv_chain);
        offset += 32;
        buf[offset..offset + 4].copy_from_slice(&row.send_count.to_le_bytes());
        offset += 4;
        buf[offset..offset + 4].copy_from_slice(&row.recv_count.to_le_bytes());
        buf
    }

    fn decode_ratchet_bytes(buf: &[u8; Self::RATCHET_SIZE]) -> RatchetStateRow {
        let mut offset = 0;
        let mut identity = [0u8; 32];
        identity.copy_from_slice(&buf[offset..offset + 32]);
        offset += 32;
        let mut root = [0u8; 32];
        root.copy_from_slice(&buf[offset..offset + 32]);
        offset += 32;
        let mut send_chain = [0u8; 32];
        send_chain.copy_from_slice(&buf[offset..offset + 32]);
        offset += 32;
        let mut recv_chain = [0u8; 32];
        recv_chain.copy_from_slice(&buf[offset..offset + 32]);
        offset += 32;
        let send_count = u32::from_le_bytes(buf[offset..offset + 4].try_into().unwrap());
        offset += 4;
        let recv_count = u32::from_le_bytes(buf[offset..offset + 4].try_into().unwrap());
        RatchetStateRow {
            identity: IdentityIdentifier(identity),
            root_key: root,
            send_chain,
            recv_chain,
            send_count,
            recv_count,
        }
    }
}

impl Zeroize for WalRecord {
    fn zeroize(&mut self) {
        if let WalRecord::UpsertRatchet { ciphertext, .. } = self {
            ciphertext.zeroize();
        }
    }
}

pub struct SecureFrame {
    pub interface: SyncInterface,
    pub nonce: u64,
    pub payload: Vec<u8>,
    pub mac: [u8; 32],
}

#[derive(Clone, Copy)]
pub enum SyncInterface {
    Uart = 0,
    Usb = 1,
    Spi = 2,
}

struct FlashCounter {
    vault: SecureVault,
    value: u64,
}

impl FlashCounter {
    fn new() -> Result<Self, IdentityError> {
        let vault = SecureVault::new();
        let (value, needs_init) = match vault.load_application_secret(VaultSlot::SyncNonceCounter) {
            Ok(bytes) => {
                let mut le = [0u8; 8];
                le.copy_from_slice(&bytes[..8]);
                (u64::from_le_bytes(le), false)
            }
            Err(IdentityError::StorageNotFound) => (0, true),
            Err(err) => return Err(err),
        };
        let counter = Self { vault, value };
        if needs_init {
            counter.persist(value)?;
        }
        Ok(counter)
    }

    fn next(&mut self) -> Result<u64, IdentityError> {
        let next = self
            .value
            .checked_add(1)
            .ok_or(IdentityError::NonceExhausted)?;
        self.persist(next)?;
        self.value = next;
        Ok(next)
    }

    fn persist(&self, value: u64) -> Result<(), IdentityError> {
        let mut buf = [0u8; 32];
        buf[..8].copy_from_slice(&value.to_le_bytes());
        self.vault
            .store_application_secret(VaultSlot::SyncNonceCounter, &buf)
    }
}

impl SecureStore {
    pub fn new(encryption_key: [u8; 32], mac_key: [u8; 32]) -> Result<Self, IdentityError> {
        Ok(Self {
            ratchets: Vec::new(),
            contacts: Vec::new(),
            wal_shadow: Vec::new(),
            wal_dirty: false,
            cipher: SecureCipher::new(encryption_key, mac_key),
            counter: FlashCounter::new()?,
            wal_nonce: 1,
        })
    }

    fn next_wal_nonce(&mut self) -> u64 {
        let nonce = self.wal_nonce;
        self.wal_nonce = self.wal_nonce.wrapping_add(1).max(1);
        nonce
    }

    pub fn begin_transaction(&self) -> WalTransaction {
        WalTransaction {
            records: Vec::new(),
        }
    }

    pub fn recover(&mut self) -> Result<(), IdentityError> {
        if self.wal_dirty {
            self.apply_records(&self.wal_shadow);
            self.wal_dirty = false;
            self.clear_wal_shadow();
        }
        Ok(())
    }

    pub fn commit(&mut self, tx: WalTransaction) -> Result<(), IdentityError> {
        if tx.records.is_empty() {
            return Ok(());
        }
        self.encrypt_wal_ops(&tx.records);
        self.wal_dirty = true;
        self.apply_records(&self.wal_shadow);
        self.wal_dirty = false;
        self.clear_wal_shadow();
        Ok(())
    }

    fn encrypt_wal_ops(&mut self, ops: &[WalOp]) {
        self.clear_wal_shadow();
        for op in ops {
            match op {
                WalOp::UpsertRatchet(row) => {
                    let nonce = self.next_wal_nonce();
                    self.wal_shadow.push(WalRecord::encrypt_ratchet(
                        row,
                        nonce,
                        &self.cipher,
                    ));
                }
                WalOp::UpsertContact(meta) => {
                    self.wal_shadow.push(WalRecord::UpsertContact(*meta))
                }
                WalOp::DeleteContact(id) => self.wal_shadow.push(WalRecord::DeleteContact(*id)),
            }
        }
    }

    fn clear_wal_shadow(&mut self) {
        for record in &mut self.wal_shadow {
            record.zeroize();
        }
        self.wal_shadow.clear();
    }

    fn apply_records(&mut self, records: &[WalRecord]) {
        for record in records {
            match record {
                WalRecord::UpsertRatchet { .. } => {
                    if let Some(entry) = record.decrypt_ratchet(&self.cipher) {
                        self.upsert_ratchet_entry(entry);
                    }
                }
                WalRecord::UpsertContact(meta) => self.upsert_contact_entry(*meta),
                WalRecord::DeleteContact(id) => self.remove_contact_entry(*id),
            }
        }
    }

    fn upsert_ratchet_entry(&mut self, entry: RatchetStateRow) {
        if let Some(existing) = self
            .ratchets
            .iter_mut()
            .find(|row| row.identity == entry.identity)
        {
            *existing = entry;
        } else {
            self.ratchets.push(entry);
        }
    }

    fn upsert_contact_entry(&mut self, meta: ContactMetadata) {
        if let Some(existing) = self
            .contacts
            .iter_mut()
            .find(|row| row.identity == meta.identity)
        {
            *existing = meta;
        } else {
            self.contacts.push(meta);
        }
    }

    fn remove_contact_entry(&mut self, identity: IdentityIdentifier) {
        if let Some(idx) = self
            .contacts
            .iter()
            .position(|row| row.identity == identity)
        {
            self.contacts.swap_remove(idx);
        }
    }

    pub fn snapshot(&mut self, interface: SyncInterface) -> Result<SecureFrame, IdentityError> {
        let payload = self.encode_records();
        let nonce = self.counter.next()?;
        Ok(self.cipher.wrap(interface, nonce, payload.as_slice()))
    }

    pub fn apply_sync_frame(&mut self, frame: &SecureFrame) -> Result<(), IdentityError> {
        let plaintext = self.cipher.unwrap(frame)?;
        let zeroized = Zeroizing::new(plaintext);
        let (ratchets, contacts) = decode_records(&zeroized)?;
        self.ratchets = ratchets;
        self.contacts = contacts;
        Ok(())
    }

    fn encode_records(&self) -> Zeroizing<Vec<u8>> {
        let mut buf = Zeroizing::new(Vec::new());
        buf.push(RECORD_VERSION);

        let ratchet_len = self.ratchets.len() as u16;
        buf.extend_from_slice(&ratchet_len.to_le_bytes());
        for row in &self.ratchets {
            buf.extend_from_slice(row.identity.as_bytes());
            buf.extend_from_slice(&row.root_key);
            buf.extend_from_slice(&row.send_chain);
            buf.extend_from_slice(&row.recv_chain);
            buf.extend_from_slice(&row.send_count.to_le_bytes());
            buf.extend_from_slice(&row.recv_count.to_le_bytes());
        }

        let contact_len = self.contacts.len() as u16;
        buf.extend_from_slice(&contact_len.to_le_bytes());
        for meta in &self.contacts {
            buf.extend_from_slice(meta.identity.as_bytes());
            buf.extend_from_slice(&meta.capabilities.bits().to_le_bytes());
            buf.extend_from_slice(&meta.last_seen_epoch.to_le_bytes());
            buf.push(meta.trust_level);
        }

        buf
    }
}

impl WalTransaction {
    pub fn upsert_ratchet(&mut self, row: RatchetStateRow) {
        self.records.push(WalOp::UpsertRatchet(row));
    }

    pub fn upsert_contact(&mut self, meta: ContactMetadata) {
        self.records.push(WalOp::UpsertContact(meta));
    }

    pub fn delete_contact(&mut self, identity: IdentityIdentifier) {
        self.records.push(WalOp::DeleteContact(identity));
    }

    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }
}

fn decode_records(
    buf: &[u8],
) -> Result<(Vec<RatchetStateRow>, Vec<ContactMetadata>), IdentityError> {
    if buf.is_empty() {
        return Err(IdentityError::StorageCorrupted);
    }
    if buf[0] != RECORD_VERSION {
        return Err(IdentityError::StorageVersionMismatch);
    }
    let mut idx = 1usize;
    if buf.len() < idx + 2 {
        return Err(IdentityError::StorageCorrupted);
    }
    let ratchet_count = u16::from_le_bytes([buf[idx], buf[idx + 1]]) as usize;
    idx += 2;

    let mut ratchets = Vec::with_capacity(ratchet_count);
    for _ in 0..ratchet_count {
        if buf.len() < idx + 32 * 4 + 8 {
            return Err(IdentityError::StorageCorrupted);
        }
        let mut identity = [0u8; 32];
        identity.copy_from_slice(&buf[idx..idx + 32]);
        idx += 32;
        let mut root = [0u8; 32];
        root.copy_from_slice(&buf[idx..idx + 32]);
        idx += 32;
        let mut send_chain = [0u8; 32];
        send_chain.copy_from_slice(&buf[idx..idx + 32]);
        idx += 32;
        let mut recv_chain = [0u8; 32];
        recv_chain.copy_from_slice(&buf[idx..idx + 32]);
        idx += 32;
        let send_count = u32::from_le_bytes(buf[idx..idx + 4].try_into().unwrap());
        idx += 4;
        let recv_count = u32::from_le_bytes(buf[idx..idx + 4].try_into().unwrap());
        idx += 4;

        ratchets.push(RatchetStateRow {
            identity: IdentityIdentifier(identity),
            root_key: root,
            send_chain,
            recv_chain,
            send_count,
            recv_count,
        });
    }

    if buf.len() < idx + 2 {
        return Err(IdentityError::StorageCorrupted);
    }
    let contact_count = u16::from_le_bytes([buf[idx], buf[idx + 1]]) as usize;
    idx += 2;

    let mut contacts = Vec::with_capacity(contact_count);
    for _ in 0..contact_count {
        if buf.len() < idx + 32 + 4 + 8 + 1 {
            return Err(IdentityError::StorageCorrupted);
        }
        let mut identity = [0u8; 32];
        identity.copy_from_slice(&buf[idx..idx + 32]);
        idx += 32;
        let capabilities = u32::from_le_bytes(buf[idx..idx + 4].try_into().unwrap());
        idx += 4;
        let last_seen = u64::from_le_bytes(buf[idx..idx + 8].try_into().unwrap());
        idx += 8;
        let trust = buf[idx];
        idx += 1;

        contacts.push(ContactMetadata {
            identity: IdentityIdentifier(identity),
            capabilities: CapabilityFlags::from_bits(capabilities),
            last_seen_epoch: last_seen,
            trust_level: trust,
        });
    }

    Ok((ratchets, contacts))
}

impl SyncInterface {
    pub fn as_byte(self) -> u8 {
        self as u8
    }

    pub fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            0 => Some(SyncInterface::Uart),
            1 => Some(SyncInterface::Usb),
            2 => Some(SyncInterface::Spi),
            _ => None,
        }
    }
}

struct SecureCipher {
    enc_key: [u8; 32],
    mac_key: [u8; 32],
}

impl SecureCipher {
    pub fn new(enc_key: [u8; 32], mac_key: [u8; 32]) -> Self {
        Self { enc_key, mac_key }
    }

    pub fn wrap(&self, interface: SyncInterface, nonce: u64, data: &[u8]) -> SecureFrame {
        let mut payload = data.to_vec();
        self.xor_keystream(nonce, &mut payload);
        let mac = self.compute_mac(interface, nonce, &payload);
        SecureFrame {
            interface,
            nonce,
            payload,
            mac,
        }
    }

    pub fn unwrap(&self, frame: &SecureFrame) -> Result<Vec<u8>, IdentityError> {
        let expected = self.compute_mac(frame.interface, frame.nonce, &frame.payload);
        if !constant_time_eq(&expected, &frame.mac) {
            return Err(IdentityError::VerificationFailed);
        }
        let mut data = frame.payload.clone();
        self.xor_keystream(frame.nonce, &mut data);
        Ok(data)
    }

    fn xor_keystream(&self, nonce: u64, data: &mut [u8]) {
        let mut counter = 0u32;
        for chunk in data.chunks_mut(32) {
            let mut mac = HmacSha256::new_from_slice(&self.enc_key).expect("enc key");
            mac.update(&nonce.to_le_bytes());
            mac.update(&counter.to_le_bytes());
            let mut block = mac.finalize().into_bytes();
            for (byte, ks) in chunk.iter_mut().zip(block.iter()) {
                *byte ^= ks;
            }
            block.zeroize();
            counter = counter.wrapping_add(1);
        }
    }

    fn compute_mac(&self, interface: SyncInterface, nonce: u64, data: &[u8]) -> [u8; 32] {
        let mut mac = HmacSha256::new_from_slice(&self.mac_key).expect("mac key");
        mac.update(&[interface.as_byte()]);
        mac.update(&nonce.to_le_bytes());
        mac.update(data);
        let digest = mac.finalize().into_bytes();
        let mut out = [0u8; 32];
        out.copy_from_slice(&digest);
        out
    }
}

fn constant_time_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    a.ct_eq(b).unwrap_u8() == 1
}
