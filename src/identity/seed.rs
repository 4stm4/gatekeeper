use sha2::{Digest, Sha256};

use crate::error::IdentityError;
use crate::identity::types::RootKey;

pub const SEED_WORD_COUNT: usize = 34;
pub const WORDLIST_SIZE: usize = 256;

const WORDLIST: [&str; WORDLIST_SIZE] = [
    "gate000", "gate001", "gate002", "gate003", "gate004", "gate005", "gate006", "gate007",
    "gate008", "gate009", "gate010", "gate011", "gate012", "gate013", "gate014", "gate015",
    "gate016", "gate017", "gate018", "gate019", "gate020", "gate021", "gate022", "gate023",
    "gate024", "gate025", "gate026", "gate027", "gate028", "gate029", "gate030", "gate031",
    "gate032", "gate033", "gate034", "gate035", "gate036", "gate037", "gate038", "gate039",
    "gate040", "gate041", "gate042", "gate043", "gate044", "gate045", "gate046", "gate047",
    "gate048", "gate049", "gate050", "gate051", "gate052", "gate053", "gate054", "gate055",
    "gate056", "gate057", "gate058", "gate059", "gate060", "gate061", "gate062", "gate063",
    "gate064", "gate065", "gate066", "gate067", "gate068", "gate069", "gate070", "gate071",
    "gate072", "gate073", "gate074", "gate075", "gate076", "gate077", "gate078", "gate079",
    "gate080", "gate081", "gate082", "gate083", "gate084", "gate085", "gate086", "gate087",
    "gate088", "gate089", "gate090", "gate091", "gate092", "gate093", "gate094", "gate095",
    "gate096", "gate097", "gate098", "gate099", "gate100", "gate101", "gate102", "gate103",
    "gate104", "gate105", "gate106", "gate107", "gate108", "gate109", "gate110", "gate111",
    "gate112", "gate113", "gate114", "gate115", "gate116", "gate117", "gate118", "gate119",
    "gate120", "gate121", "gate122", "gate123", "gate124", "gate125", "gate126", "gate127",
    "gate128", "gate129", "gate130", "gate131", "gate132", "gate133", "gate134", "gate135",
    "gate136", "gate137", "gate138", "gate139", "gate140", "gate141", "gate142", "gate143",
    "gate144", "gate145", "gate146", "gate147", "gate148", "gate149", "gate150", "gate151",
    "gate152", "gate153", "gate154", "gate155", "gate156", "gate157", "gate158", "gate159",
    "gate160", "gate161", "gate162", "gate163", "gate164", "gate165", "gate166", "gate167",
    "gate168", "gate169", "gate170", "gate171", "gate172", "gate173", "gate174", "gate175",
    "gate176", "gate177", "gate178", "gate179", "gate180", "gate181", "gate182", "gate183",
    "gate184", "gate185", "gate186", "gate187", "gate188", "gate189", "gate190", "gate191",
    "gate192", "gate193", "gate194", "gate195", "gate196", "gate197", "gate198", "gate199",
    "gate200", "gate201", "gate202", "gate203", "gate204", "gate205", "gate206", "gate207",
    "gate208", "gate209", "gate210", "gate211", "gate212", "gate213", "gate214", "gate215",
    "gate216", "gate217", "gate218", "gate219", "gate220", "gate221", "gate222", "gate223",
    "gate224", "gate225", "gate226", "gate227", "gate228", "gate229", "gate230", "gate231",
    "gate232", "gate233", "gate234", "gate235", "gate236", "gate237", "gate238", "gate239",
    "gate240", "gate241", "gate242", "gate243", "gate244", "gate245", "gate246", "gate247",
    "gate248", "gate249", "gate250", "gate251", "gate252", "gate253", "gate254", "gate255",
];

#[derive(Clone)]
pub struct SeedPhrase {
    indices: [u8; SEED_WORD_COUNT],
}

impl SeedPhrase {
    pub fn from_root(root: &RootKey) -> Self {
        let mut indices = [0u8; SEED_WORD_COUNT];
        for (dst, src) in indices.iter_mut().take(32).zip(root.0.iter()) {
            *dst = *src;
        }
        let checksum = checksum_bytes(&root.0);
        indices[32] = checksum[0];
        indices[33] = checksum[1];
        Self { indices }
    }

    pub fn words(&self) -> [&'static str; SEED_WORD_COUNT] {
        let mut out = [""; SEED_WORD_COUNT];
        for (i, idx) in self.indices.iter().enumerate() {
            out[i] = WORDLIST[*idx as usize];
        }
        out
    }

    pub fn from_words(words: [&str; SEED_WORD_COUNT]) -> Result<Self, IdentityError> {
        let mut indices = [0u8; SEED_WORD_COUNT];
        for (i, word) in words.iter().enumerate() {
            indices[i] = word_index(word).ok_or(IdentityError::InvalidSeed)?;
        }
        let phrase = Self { indices };
        phrase.validate()?;
        Ok(phrase)
    }

    pub fn from_slice(words: &[&str]) -> Result<Self, IdentityError> {
        if words.len() != SEED_WORD_COUNT {
            return Err(IdentityError::InvalidSeed);
        }
        let mut arr = [""; SEED_WORD_COUNT];
        for (dst, src) in arr.iter_mut().zip(words.iter()) {
            *dst = src;
        }
        Self::from_words(arr)
    }

    pub fn recover_root(&self) -> Result<RootKey, IdentityError> {
        self.validate()?;
        let mut root = [0u8; 32];
        root.copy_from_slice(&self.indices[..32]);
        Ok(RootKey(root))
    }

    pub fn indices(&self) -> &[u8; SEED_WORD_COUNT] {
        &self.indices
    }

    fn validate(&self) -> Result<(), IdentityError> {
        let mut root = [0u8; 32];
        root.copy_from_slice(&self.indices[..32]);
        let checksum = checksum_bytes(&root);
        if self.indices[32] != checksum[0] || self.indices[33] != checksum[1] {
            return Err(IdentityError::InvalidSeed);
        }
        Ok(())
    }
}

fn checksum_bytes(root: &[u8; 32]) -> [u8; 2] {
    let mut hasher = Sha256::new();
    hasher.update(root);
    let digest = hasher.finalize();
    [digest[0], digest[1]]
}

fn word_index(word: &str) -> Option<u8> {
    WORDLIST
        .iter()
        .position(|candidate| *candidate == word)
        .map(|idx| idx as u8)
}
