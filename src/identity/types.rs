//! Базовые типы (ключи, идентификаторы и состояние личности).
use crate::identity::keys;
use sha2::{Digest, Sha256};

/// Корневой ключ личности (`root_key`), общий для всех устройств.
#[derive(Clone)]
pub struct RootKey(pub(crate) [u8; 32]);
/// Пользовательский секрет (`sk_user`) конкретного устройства.
#[derive(Clone)]
pub struct UserSecret(pub(crate) [u8; 32]);
/// Деталь устройства, участвующая в HKDF.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeviceId(pub [u8; 16]);

/// Публичный ключ личности, пригодный для публикации.
#[derive(Clone, Copy)]
pub struct UserPublicKey(pub [u8; 32]);
/// Хэшированный идентификатор личности, используемый verifier'ом.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct IdentityIdentifier(pub [u8; 32]);

impl RootKey {
    /// Создаёт root key из заранее подготовленного массива.
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Возвращает байтовое представление.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Рабочее состояние личности (root, device_id, секрет).
pub struct IdentityState {
    pub(crate) root_key: RootKey,
    pub(crate) device_id: DeviceId,
    pub(crate) sk_user: UserSecret,
}

impl IdentityState {
    /// Возвращает текущий `DeviceId`.
    pub fn device_id(&self) -> DeviceId {
        self.device_id
    }

    /// Возвращает ссылку на корневой ключ.
    pub fn root_key(&self) -> &RootKey {
        &self.root_key
    }

    /// Вычисляет публичный ключ без обращения к Flash.
    pub fn public_key(&self) -> UserPublicKey {
        let bytes = keys::public_key_from_secret(&self.sk_user.0);
        UserPublicKey(bytes)
    }

    /// Возвращает детерминированный идентификатор личности (`H(PK)`).
    pub fn identifier(&self) -> IdentityIdentifier {
        self.public_key().into_identifier()
    }
}

impl UserPublicKey {
    /// Ссылка на байтовое представление.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Потребляет структуру и возвращает массив.
    pub fn into_bytes(self) -> [u8; 32] {
        self.0
    }

    /// Конвертирует публичный ключ в идентификатор (SHA-256).
    pub fn into_identifier(self) -> IdentityIdentifier {
        IdentityIdentifier::from_public_key(&self.0)
    }
}

impl IdentityIdentifier {
    /// Создаёт идентификатор из публичного ключа.
    pub fn from_public_key(pk: &[u8; 32]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(b"zk-gatekeeper-identity");
        hasher.update(pk);
        let digest = hasher.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&digest);
        IdentityIdentifier(out)
    }

    /// Возвращает байтовое представление.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Проверяет, соответствует ли заданный PK текущему идентификатору.
    pub fn matches(&self, pk: &[u8; 32]) -> bool {
        let derived = IdentityIdentifier::from_public_key(pk);
        derived.0 == self.0
    }
}
