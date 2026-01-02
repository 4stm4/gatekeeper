use zk_gatekeeper::identity::entropy::{
    EntropySource, FallbackEntropy, MockEntropy, PseudoEntropy,
};

#[test]
fn mock_entropy_cycles_input() {
    let pattern = [1u8, 2, 3, 4];
    let mut mock = MockEntropy::from_slice(&pattern);
    let mut out = [0u8; 6];
    mock.fill_bytes(&mut out).unwrap();
    assert_eq!(&out, &[1, 2, 3, 4, 1, 2]);
}

#[test]
fn fallback_switches_to_pseudo_entropy() {
    let primary = MockEntropy::unavailable();
    let secondary = PseudoEntropy::new([0x55u8; 32]);
    let mut fallback = FallbackEntropy::new(primary, secondary);
    let mut out = [0u8; 32];
    fallback.fill_bytes(&mut out).unwrap();
    assert_ne!(&out, &[0u8; 32]);
}
