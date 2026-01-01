use crate::error::IdentityError;

pub trait EntropySource {
    fn fill_bytes(&mut self, out: &mut [u8]) -> Result<(), IdentityError>;
}

pub struct DummyEntropy;

impl EntropySource for DummyEntropy {
    fn fill_bytes(&mut self, out: &mut [u8]) -> Result<(), IdentityError> {
        for (i, byte) in out.iter_mut().enumerate() {
            *byte = (i & 0xFF) as u8;
        }
        Ok(())
    }
}
