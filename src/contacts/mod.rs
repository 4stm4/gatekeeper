//! Контроллер Merkle-дерева доверенных контактов и подготовка входов для ZK.

use alloc::vec::Vec;

use crate::error::IdentityError;
use crate::identity::types::UserPublicKey;

mod poseidon;
/// Переиспользуемые Poseidon-хеши (для бенчмарков/интеграций).
pub use poseidon::{hash_leaf as poseidon_hash_leaf, hash_pair as poseidon_hash_pair};

/// Глубина бинарного дерева контактов (2^depth листьев).
pub const CONTACT_TREE_DEPTH: usize = 8;
/// Максимальное количество контактов, поддерживаемое деревом.
pub const MAX_CONTACTS: usize = 1 << CONTACT_TREE_DEPTH;
const EMPTY_LEAF: [u8; 32] = [0u8; 32];

/// Полное состояние дерева контактов с предвычисленным корнем.
#[derive(Clone)]
pub struct ContactTree {
    leaves: Vec<[u8; 32]>,
    occupied: Vec<bool>,
    root: [u8; 32],
}

/// Свидетельство членства в дереве (для передачи verifier'у).
pub struct ContactWitness {
    pub leaf: [u8; 32],
    pub siblings: Vec<[u8; 32]>,
    pub path: Vec<bool>,
    pub root: [u8; 32],
}

/// Подготовленные входы для zk-гостя.
pub struct ZkMembershipInputs {
    pub root: [u8; 32],
    pub leaf: [u8; 32],
    pub siblings: Vec<[u8; 32]>,
    pub path_bits: Vec<bool>,
}

impl ContactTree {
    /// Создаёт пустое дерево и вычисляет корень.
    pub fn new() -> Self {
        let leaves = vec![EMPTY_LEAF; MAX_CONTACTS];
        let occupied = vec![false; MAX_CONTACTS];
        let mut tree = Self {
            leaves,
            occupied,
            root: EMPTY_LEAF,
        };
        tree.root = tree.compute_root();
        tree
    }

    /// Возвращает текущий корень.
    pub fn root(&self) -> [u8; 32] {
        self.root
    }

    /// Алиас API для совместимости с хранениям.
    pub fn contact_set_root(&self) -> [u8; 32] {
        self.root()
    }

    /// Добавляет публичный ключ в дерево, возвращая ошибку при коллизиях или переполнении.
    pub fn add_contact(&mut self, pk: &UserPublicKey) -> Result<(), IdentityError> {
        let leaf = poseidon::hash_leaf(pk.as_bytes());
        if self.find_leaf(&leaf).is_some() {
            return Err(IdentityError::ContactAlreadyExists);
        }
        if let Some(idx) = self.free_slot() {
            self.leaves[idx] = leaf;
            self.occupied[idx] = true;
            self.root = self.compute_root();
            Ok(())
        } else {
            Err(IdentityError::ContactListFull)
        }
    }

    /// Удаляет существующий контакт.
    pub fn remove_contact(&mut self, pk: &UserPublicKey) -> Result<(), IdentityError> {
        let leaf = poseidon::hash_leaf(pk.as_bytes());
        if let Some(idx) = self.find_leaf(&leaf) {
            self.leaves[idx] = EMPTY_LEAF;
            self.occupied[idx] = false;
            self.root = self.compute_root();
            Ok(())
        } else {
            Err(IdentityError::ContactNotFound)
        }
    }

    /// Возвращает свидетельство членства для конкретного PK.
    pub fn membership_proof(&self, pk: &UserPublicKey) -> Result<ContactWitness, IdentityError> {
        let leaf = poseidon::hash_leaf(pk.as_bytes());
        let index = self
            .find_leaf(&leaf)
            .ok_or(IdentityError::ContactNotFound)?;

        let (siblings, bits) = self.compute_path(index);
        Ok(ContactWitness {
            leaf,
            siblings,
            path: bits,
            root: self.root,
        })
    }

    /// Быстрая проверка наличия контакта без построения witness.
    pub fn contains(&self, pk: &UserPublicKey) -> bool {
        let leaf = poseidon::hash_leaf(pk.as_bytes());
        self.find_leaf(&leaf).is_some()
    }

    fn free_slot(&self) -> Option<usize> {
        self.occupied.iter().position(|slot| !*slot)
    }

    fn find_leaf(&self, leaf: &[u8; 32]) -> Option<usize> {
        self.leaves
            .iter()
            .zip(self.occupied.iter())
            .position(|(candidate, occ)| *occ && candidate == leaf)
    }

    fn compute_root(&self) -> [u8; 32] {
        let mut level = self.leaves.clone();
        let mut width = level.len();

        while width > 1 {
            let mut next = vec![EMPTY_LEAF; width / 2];
            for i in 0..(width / 2) {
                let left = level[2 * i];
                let right = level[2 * i + 1];
                next[i] = poseidon::hash_pair(&left, &right);
            }
            level = next;
            width /= 2;
        }

        level[0]
    }

    fn compute_path(&self, mut index: usize) -> (Vec<[u8; 32]>, Vec<bool>) {
        let mut level = self.leaves.clone();
        let mut siblings = Vec::with_capacity(CONTACT_TREE_DEPTH);
        let mut bits = Vec::with_capacity(CONTACT_TREE_DEPTH);
        let mut width = level.len();

        for _ in 0..CONTACT_TREE_DEPTH {
            let is_right = index % 2 == 1;
            let sibling_idx = if is_right {
                index - 1
            } else {
                (index + 1).min(width - 1)
            };
            siblings.push(level[sibling_idx]);
            bits.push(is_right);

            let mut next = vec![EMPTY_LEAF; width / 2];
            for i in 0..(width / 2) {
                let left = level[2 * i];
                let right = level[2 * i + 1];
                next[i] = poseidon::hash_pair(&left, &right);
            }
            level = next;
            width /= 2;
            index /= 2;
        }

        (siblings, bits)
    }
}

impl ContactWitness {
    /// Конвертирует свидетельство в структуру для ZK-гостя.
    pub fn prepare_zk_inputs(&self) -> ZkMembershipInputs {
        ZkMembershipInputs {
            root: self.root,
            leaf: self.leaf,
            siblings: self.siblings.clone(),
            path_bits: self.path.clone(),
        }
    }

    /// Проверяет, что свернутый путь даёт исходный `root`.
    pub fn verify(&self) -> bool {
        verify_membership_path(&self.leaf, &self.siblings, &self.path, &self.root)
    }
}

/// Проверяет, что `leaf` принадлежит дереву с корнем `root` и путём `siblings`.
pub fn verify_membership_path(
    leaf: &[u8; 32],
    siblings: &[[u8; 32]],
    path_bits: &[bool],
    expected_root: &[u8; 32],
) -> bool {
    if siblings.len() != CONTACT_TREE_DEPTH || path_bits.len() != CONTACT_TREE_DEPTH {
        return false;
    }
    let mut acc = *leaf;
    for (level, (sibling, is_right)) in siblings.iter().zip(path_bits.iter()).enumerate() {
        acc = if *is_right {
            poseidon::hash_pair(sibling, &acc)
        } else {
            poseidon::hash_pair(&acc, sibling)
        };
        if level == CONTACT_TREE_DEPTH - 1 {
            // nothing special
        }
    }
    acc == *expected_root
}
