use alloc::vec::Vec;
use core::convert::TryInto;

use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::error::IdentityError;
use crate::handshake::CapabilityFlags;
use crate::identity::types::IdentityIdentifier;

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
    next_nonce: u32,
}

pub struct WalTransaction {
    records: Vec<WalRecord>,
}

#[derive(Clone)]
enum WalRecord {
    UpsertRatchet(RatchetStateRow),
    UpsertContact(ContactMetadata),
    DeleteContact(IdentityIdentifier),
}

pub struct SecureFrame {
    pub interface: SyncInterface,
    pub nonce: u32,
    pub payload: Vec<u8>,
    pub mac: [u8; 32],
}

#[derive(Clone, Copy)]
pub enum SyncInterface {
    Uart = 0,
    Usb = 1,
    Spi = 2,
}

impl SecureStore {
    pub fn new(encryption_key: [u8; 32], mac_key: [u8; 32]) -> Self {
        Self {
            ratchets: Vec::new(),
            contacts: Vec::new(),
            wal_shadow: Vec::new(),
            wal_dirty: false,
            cipher: SecureCipher::new(encryption_key, mac_key),
            next_nonce: 1,
        }
    }

    pub fn begin_transaction(&self) -> WalTransaction {
        WalTransaction {
            records: Vec::new(),
        }
    }

    pub fn recover(&mut self) -> Result<(), IdentityError> {
        if self.wal_dirty {
            let shadow = self.wal_shadow.clone();
            self.apply_records(&shadow);
            self.wal_dirty = false;
            self.wal_shadow.clear();
        }
        Ok(())
    }

    pub fn commit(&mut self, tx: WalTransaction) -> Result<(), IdentityError> {
        if tx.records.is_empty() {
            return Ok(());
        }
        self.wal_shadow = tx.records.clone();
        self.wal_dirty = true;
        self.apply_records(&tx.records);
        self.wal_dirty = false;
        self.wal_shadow.clear();
        Ok(())
    }

    fn apply_records(&mut self, records: &[WalRecord]) {
        for record in records {
            match record {
                WalRecord::UpsertRatchet(entry) => self.upsert_ratchet_entry(*entry),
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

    pub fn snapshot(&mut self, interface: SyncInterface) -> SecureFrame {
        let payload = self.encode_records();
        let nonce = self.next_nonce;
        self.next_nonce = self.next_nonce.wrapping_add(1);
        self.cipher.wrap(interface, nonce, &payload)
    }

    pub fn apply_sync_frame(&mut self, frame: &SecureFrame) -> Result<(), IdentityError> {
        let plaintext = self.cipher.unwrap(frame)?;
        let (ratchets, contacts) = decode_records(&plaintext)?;
        self.ratchets = ratchets;
        self.contacts = contacts;
        Ok(())
    }

    fn encode_records(&self) -> Vec<u8> {
        let mut buf = Vec::new();
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
        self.records.push(WalRecord::UpsertRatchet(row));
    }

    pub fn upsert_contact(&mut self, meta: ContactMetadata) {
        self.records.push(WalRecord::UpsertContact(meta));
    }

    pub fn delete_contact(&mut self, identity: IdentityIdentifier) {
        self.records.push(WalRecord::DeleteContact(identity));
    }

    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }
}

fn decode_records(buf: &[u8]) -> Result<(Vec<RatchetStateRow>, Vec<ContactMetadata>), IdentityError> {
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

    pub fn wrap(&self, interface: SyncInterface, nonce: u32, data: &[u8]) -> SecureFrame {
        let mut payload = data.to_vec();
        self.apply_keystream(nonce, &mut payload);
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
        self.apply_keystream(frame.nonce, &mut data);
        Ok(data)
    }

    fn apply_keystream(&self, nonce: u32, data: &mut [u8]) {
        let mut counter = 0u32;
        for chunk in data.chunks_mut(32) {
            let mut mac = HmacSha256::new_from_slice(&self.enc_key).expect("enc key");
            mac.update(&nonce.to_le_bytes());
            mac.update(&counter.to_le_bytes());
            let block = mac.finalize().into_bytes();
            for (byte, ks) in chunk.iter_mut().zip(block.iter()) {
                *byte ^= ks;
            }
            counter = counter.wrapping_add(1);
        }
    }

    fn compute_mac(&self, interface: SyncInterface, nonce: u32, data: &[u8]) -> [u8; 32] {
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
    let mut diff = 0u8;
    for i in 0..32 {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}
