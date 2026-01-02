use hmac::{Hmac, Mac};
use sha2::Sha256;

const LABEL_ROOT: &[u8] = b"ratchet-root";
const LABEL_SEND: &[u8] = b"ratchet-send";
const LABEL_RECV: &[u8] = b"ratchet-recv";

type HmacSha256 = Hmac<Sha256>;

#[derive(Clone)]
pub struct RatchetState {
    root_key: [u8; 32],
    send_chain: [u8; 32],
    recv_chain: [u8; 32],
    send_count: u32,
    recv_count: u32,
}

impl RatchetState {
    pub fn new(shared_secret: [u8; 32]) -> Self {
        let root_key = kdf(&shared_secret, LABEL_ROOT);
        let send_chain = kdf(&root_key, LABEL_SEND);
        let recv_chain = kdf(&root_key, LABEL_RECV);
        Self {
            root_key,
            send_chain,
            recv_chain,
            send_count: 0,
            recv_count: 0,
        }
    }

    pub fn next_send_key(&mut self) -> [u8; 32] {
        self.send_count = self.send_count.wrapping_add(1);
        self.send_chain = kdf(&self.send_chain, LABEL_SEND);
        self.send_chain
    }

    pub fn next_recv_key(&mut self) -> [u8; 32] {
        self.recv_count = self.recv_count.wrapping_add(1);
        self.recv_chain = kdf(&self.recv_chain, LABEL_RECV);
        self.recv_chain
    }

    pub fn root_key(&self) -> &[u8; 32] {
        &self.root_key
    }
}

fn kdf(key: &[u8; 32], label: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(label).expect("label");
    mac.update(key);
    let digest = mac.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}
