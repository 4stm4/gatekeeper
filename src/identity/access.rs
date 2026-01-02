use core::marker::PhantomData;

use crate::error::IdentityError;
use crate::identity::types::*;
use crate::zk::proof::ZkProof;
use crate::zk::prover::ZkProver;

pub struct ZkSecretRef<'a> {
    pub(crate) secret: &'a UserSecret,
    _nosend: PhantomData<*const ()>,
}

impl IdentityState {
    pub fn zk_secret(&self) -> Result<ZkSecretRef<'_>, IdentityError> {
        Ok(ZkSecretRef {
            secret: &self.sk_user,
            _nosend: PhantomData,
        })
    }

    pub fn prove_with<P: ZkProver>(
        &self,
        prover: &P,
        challenge: &[u8],
    ) -> Result<ZkProof, IdentityError> {
        let secret = self.zk_secret()?;
        prover.prove(secret, challenge)
    }
}
