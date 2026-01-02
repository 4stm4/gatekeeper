use proptest::collection::vec;
use proptest::prelude::*;
use zk_gatekeeper::contacts::ContactTree;
use zk_gatekeeper::identity::hkdf::{derive_storage_keys, derive_user_key};
use zk_gatekeeper::identity::types::{DeviceId, IdentityState, RootKey, UserPublicKey};
use zk_gatekeeper::zk::proof::MAX_CHALLENGE_LEN;
use zk_gatekeeper::zk::prover::DeterministicSchnorrProver;

proptest! {
    #[test]
    fn user_key_depends_on_device(root in any::<[u8; 32]>(), dev_a in any::<[u8; 16]>(), dev_b in any::<[u8; 16]>()) {
        prop_assume!(dev_a != dev_b);
        let root_key = RootKey(root);
        let k_a = derive_user_key(&root_key, &DeviceId(dev_a)).unwrap();
        let k_b = derive_user_key(&root_key, &DeviceId(dev_b)).unwrap();
        prop_assert_ne!(k_a, k_b);
    }
}

proptest! {
    #[test]
    fn storage_keys_remain_distinct(root in any::<[u8; 32]>(), device in any::<[u8; 16]>()) {
        let root_key = RootKey(root);
        let device_id = DeviceId(device);
        let (enc, mac) = derive_storage_keys(&root_key, &device_id).unwrap();
        prop_assert_ne!(enc, mac);
    }
}

proptest! {
    #[test]
    fn deterministic_schnorr_roundtrip(root in any::<[u8; 32]>(), device in any::<[u8; 16]>(), challenge in vec(any::<u8>(), 1..=MAX_CHALLENGE_LEN)) {
        let state = IdentityState::from_root(RootKey(root), DeviceId(device)).unwrap();
        let prover = DeterministicSchnorrProver::default();
        let proof = state.prove_with(&prover, &challenge).unwrap();
        let pk = state.public_key().into_bytes();
        prop_assert!(proof.verify(b"zk-gatekeeper-schnorr-v1", &challenge, &pk));
    }
}

proptest! {
    #[test]
    fn contact_tree_add_remove_is_consistent(pk in any::<[u8; 32]>()) {
        let key = UserPublicKey(pk);
        let mut tree = ContactTree::new();
        tree.add_contact(&key).unwrap();
        prop_assert!(tree.contains(&key));
        tree.remove_contact(&key).unwrap();
        prop_assert!(!tree.contains(&key));
    }
}
