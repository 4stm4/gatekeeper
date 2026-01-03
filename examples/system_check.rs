//! Интерактивная проверка основных подсистем: identity → ZK proof → Noise-канал.
use zk_gatekeeper::handshake::{CapabilityFlags, NoiseStaticKeypair};
use zk_gatekeeper::identity::entropy::{DummyEntropy, PseudoEntropy};
use zk_gatekeeper::identity::init::init_identity;
use zk_gatekeeper::identity::types::DeviceId;
use zk_gatekeeper::zk::handshake::{accept_responder, start_initiator};
use zk_gatekeeper::zk::prover::DeterministicSchnorrProver;
use zk_gatekeeper::zk::verifier::{ChallengeTrackerConfig, Verifier};

fn main() {
    println!("⏳ identity init + proof generation…");
    let mut entropy = DummyEntropy;
    let identity = init_identity(&mut entropy, DeviceId([0xAB; 16])).expect("identity init failed");

    let challenge = b"system-check-challenge";
    let prover = DeterministicSchnorrProver::default();
    let proof = identity
        .prove_with(&prover, challenge)
        .expect("proof failed");

    let mut verifier = Verifier::new(
        b"zk-gatekeeper-schnorr-v1",
        ChallengeTrackerConfig::new(4, 10),
    );
    let now = 42u64;
    verifier
        .tracker_mut()
        .register(challenge, now)
        .expect("challenge registration failed");
    verifier
        .verify(
            &identity.identifier(),
            identity.public_key().as_bytes(),
            challenge,
            now,
            &proof,
        )
        .expect("verification failed");
    println!(
        "✅ ZK proof проверен, identity {:x?}",
        identity.identifier().as_bytes()
    );

    println!("⏳ Noise-рукопожатие и защищённый канал…");
    let mut initiator_rng = PseudoEntropy::new([0x11; 32]);
    let mut responder_rng = PseudoEntropy::new([0x22; 32]);
    let initiator_static =
        NoiseStaticKeypair::new(&mut initiator_rng).expect("initiator static keypair");
    let responder_static =
        NoiseStaticKeypair::new(&mut responder_rng).expect("responder static keypair");
    let initiator_pk = initiator_static.public_key();
    let responder_pk = responder_static.public_key();

    let initiator_caps = CapabilityFlags::VOICE.union(CapabilityFlags::TEXT);
    let responder_caps = CapabilityFlags::TEXT.union(CapabilityFlags::FILES);

    let (init_msg, pending) = start_initiator(
        &initiator_static,
        &responder_pk,
        initiator_caps,
        &mut initiator_rng,
    )
    .expect("initiator start");
    let (resp_msg, mut responder_channel) = accept_responder(
        &init_msg,
        &responder_static,
        &initiator_pk,
        responder_caps,
        &mut responder_rng,
    )
    .expect("responder accept");
    let mut initiator_channel = pending
        .finish(&resp_msg, &initiator_static, &responder_pk)
        .expect("initiator finish");

    let negotiated = CapabilityFlags::TEXT;
    assert_eq!(initiator_channel.capabilities(), negotiated);
    assert_eq!(responder_channel.capabilities(), negotiated);
    println!("✅ Capability-флаги совпали: {:?}", negotiated.bits());

    let ciphertext = initiator_channel.encrypt(b"ping-from-initiator");
    let decrypted = responder_channel
        .decrypt(&ciphertext)
        .expect("decrypt on responder");
    assert_eq!(decrypted.as_slice(), b"ping-from-initiator");

    let reply = responder_channel.encrypt(b"pong-from-responder");
    let decrypted = initiator_channel
        .decrypt(&reply)
        .expect("decrypt on initiator");
    assert_eq!(decrypted.as_slice(), b"pong-from-responder");
    println!("✅ SecureChannel прошёл обмен сообщениями.");

    println!("Готово! Запусти `cargo run --example system_check` чтобы повторить проверку.");
}
