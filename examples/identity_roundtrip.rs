//! Демонстрация генерации личности и идентификатора.
use zk_gatekeeper::identity::entropy::DummyEntropy;
use zk_gatekeeper::identity::init::init_identity;
use zk_gatekeeper::identity::types::DeviceId;
use zk_gatekeeper::zk::prover::DeterministicSchnorrProver;

fn main() {
    let mut entropy = DummyEntropy;
    let device = DeviceId([0x11; 16]);
    let identity = init_identity(&mut entropy, device).expect("identity init failed");

    let identifier = identity.identifier();
    println!("identity id: {:x?}", identifier.as_bytes());

    let prover = DeterministicSchnorrProver::default();
    let challenge = b"example-challenge";
    let proof = identity
        .prove_with(&prover, challenge)
        .expect("prove failed");
    println!("proof bytes: {:x?}", proof.as_bytes());
}
