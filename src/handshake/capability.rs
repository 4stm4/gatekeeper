#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CapabilityFlags(u32);

impl CapabilityFlags {
    pub const EMPTY: Self = Self(0);
    pub const VOICE: Self = Self(1 << 0);
    pub const FILES: Self = Self(1 << 1);
    pub const TEXT: Self = Self(1 << 2);
    pub const VIDEO: Self = Self(1 << 3);

    pub const fn bits(self) -> u32 {
        self.0
    }

    pub const fn from_bits(bits: u32) -> Self {
        Self(bits)
    }

    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    pub const fn intersect(self, other: Self) -> Self {
        Self(self.0 & other.0)
    }

    pub fn is_empty(self) -> bool {
        self.0 == 0
    }
}

#[derive(Clone, Copy, Debug)]
pub struct CapabilityManager {
    local: CapabilityFlags,
    remote: CapabilityFlags,
}

impl CapabilityManager {
    pub const fn new(local: CapabilityFlags, remote: CapabilityFlags) -> Self {
        Self { local, remote }
    }

    pub const fn negotiated(&self) -> CapabilityFlags {
        self.local.intersect(self.remote)
    }
}
