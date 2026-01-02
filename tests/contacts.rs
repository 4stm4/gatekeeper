use zk_gatekeeper::contacts::ContactTree;
use zk_gatekeeper::identity::types::UserPublicKey;

fn pk(byte: u8) -> UserPublicKey {
    UserPublicKey([byte; 32])
}

#[test]
fn add_and_prove_contact() {
    let mut tree = ContactTree::new();
    let alice = pk(1);
    tree.add_contact(&alice).unwrap();
    assert!(tree.contains(&alice));

    let witness = tree.membership_proof(&alice).unwrap();
    let inputs = witness.prepare_zk_inputs();
    assert_eq!(inputs.root, tree.contact_set_root());
    assert_eq!(inputs.leaf, witness.leaf);
}

#[test]
fn revoke_contact() {
    let mut tree = ContactTree::new();
    let alice = pk(2);
    let bob = pk(3);
    tree.add_contact(&alice).unwrap();
    tree.add_contact(&bob).unwrap();
    tree.remove_contact(&alice).unwrap();
    assert!(!tree.contains(&alice));
    assert!(tree.contains(&bob));
    assert!(tree.membership_proof(&bob).is_ok());
}
