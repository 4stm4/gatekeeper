use core::cmp::min;

use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::error::IdentityError;
use crate::identity::types::{DeviceId, RootKey};

type HkdfHmac = Hmac<Sha256>;

const LABEL_USER: &[u8] = b"zk-gatekeeper-hkdf";
const LABEL_STORAGE: &[u8] = b"zk-gatekeeper-hkdf";
const CONTEXT_USER: &[u8] = b"user-key-v1";
const CONTEXT_STORAGE: &[u8] = b"storage-key-v1";

pub fn derive_user_key(root: &RootKey, device: &DeviceId) -> Result<[u8; 32], IdentityError> {
    let mut key = [0u8; 32];
    derive_labeled_material(root, device, LABEL_USER, CONTEXT_USER, &mut key)?;
    Ok(key)
}

pub fn derive_storage_keys(
    root: &RootKey,
    device: &DeviceId,
) -> Result<([u8; 32], [u8; 32]), IdentityError> {
    let mut material = [0u8; 64];
    derive_labeled_material(root, device, LABEL_STORAGE, CONTEXT_STORAGE, &mut material)?;

    let mut enc = [0u8; 32];
    let mut mac = [0u8; 32];
    enc.copy_from_slice(&material[..32]);
    mac.copy_from_slice(&material[32..]);
    material.fill(0);
    Ok((enc, mac))
}

fn derive_labeled_material(
    root: &RootKey,
    device: &DeviceId,
    label: &[u8],
    context: &[u8],
    out: &mut [u8],
) -> Result<(), IdentityError> {
    let mut prk = hkdf_extract(root, device)?;
    let mut prev = [0u8; 32];
    let mut generated = 0usize;
    let mut counter = 1u8;

    while generated < out.len() {
        let mut expand = HkdfHmac::new_from_slice(&prk)?;

        if generated != 0 {
            expand.update(&prev);
        }

        expand.update(label);
        expand.update(context);
        expand.update(&device.0);
        expand.update(&[counter]);

        let block = expand.finalize().into_bytes();
        let mut block_buf = [0u8; 32];
        block_buf.copy_from_slice(&block);

        let take = min(out.len() - generated, block_buf.len());
        out[generated..generated + take].copy_from_slice(&block_buf[..take]);
        prev.copy_from_slice(&block_buf);

        block_buf.fill(0);
        generated += take;
        counter = counter.wrapping_add(1);
    }

    prk.fill(0);
    prev.fill(0);
    Ok(())
}

fn hkdf_extract(root: &RootKey, device: &DeviceId) -> Result<[u8; 32], IdentityError> {
    let mut extract = HkdfHmac::new_from_slice(&device.0)?;
    extract.update(&root.0);
    let prk_ga = extract.finalize().into_bytes();
    let mut prk = [0u8; 32];
    prk.copy_from_slice(&prk_ga);
    Ok(prk)
}
