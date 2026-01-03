use zk_gatekeeper::identity::hkdf::{derive_storage_keys, derive_user_key};
use zk_gatekeeper::identity::types::{DeviceId, RootKey};

fn sample_root() -> RootKey {
    RootKey::from_bytes([0x11u8; 32])
}

fn sample_device() -> DeviceId {
    DeviceId([0x22u8; 16])
}

#[test]
fn user_key_deterministic() {
    let root = sample_root();
    let device = sample_device();
    let k1 = derive_user_key(&root, &device).unwrap();
    let k2 = derive_user_key(&root, &device).unwrap();
    assert_eq!(k1, k2);
}

#[test]
fn storage_keys_distinct() {
    let root = sample_root();
    let device = sample_device();
    let (enc, mac) = derive_storage_keys(&root, &device).unwrap();
    assert_ne!(enc, mac);
}
