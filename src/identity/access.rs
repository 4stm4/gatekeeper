use core::marker::PhantomData;

use crate::error::IdentityError;
use crate::identity::types::*;
use crate::zk::proof::ZkProof;
use crate::zk::prover::ZkProver;

/// Неперемещаемая ссылка на `sk_user`, доступная только внутри prove().
pub struct ZkSecretRef<'a> {
    pub(crate) secret: &'a UserSecret,
    _nosend: PhantomData<*const ()>,
}

impl IdentityState {
    /// Возвращает ссылку на `sk_user` с ограничением Send/Sync.
    pub fn zk_secret(&self) -> Result<ZkSecretRef<'_>, IdentityError> {
        Ok(ZkSecretRef {
            secret: &self.sk_user,
            _nosend: PhantomData,
        })
    }

    /// Выполняет ZK-доказательство с заданным prover'ом.
    pub fn prove_with<P: ZkProver>(
        &self,
        prover: &P,
        challenge: &[u8],
    ) -> Result<ZkProof, IdentityError> {
        let secret = self.zk_secret()?;
        prover.prove(secret, challenge)
    }
}
