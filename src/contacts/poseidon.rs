use subtle::{Choice, ConditionallySelectable};

const WIDTH: usize = 3;
const ROUNDS: usize = 8;

// Poseidon over the Goldilocks field (2^64 - 2^32 + 1), alpha = 5.
const ROUND_CONSTANTS: [[u64; WIDTH]; ROUNDS] = [
    [0x243f6a8885a308d3, 0x13198a2e03707344, 0xa4093822299f31d0],
    [0x082efa98ec4e6c89, 0x452821e638d01377, 0xbe5466cf34e90c6c],
    [0xc0ac29b7c97c50dd, 0x3f84d5b5b5470917, 0x9216d5d98979fb1b],
    [0xd1310ba698dfb5ac, 0x2ffd72dbd01adfb7, 0xb8e1afed6a267e96],
    [0xba7c9045f12c7f99, 0x24a19947b3916cf7, 0x0801f2e2858efc16],
    [0x636920d871574e69, 0xa458fea3f4933d7e, 0x0d95748f728eb658],
    [0x718bcd5882154aee, 0x7b54a41dc25a59b5, 0x9c30d5392af26013],
    [0xc5d1b023286085f0, 0xca417918b8db38ef, 0x8e79dcb0603a180e],
];

const MDS: [[u64; WIDTH]; WIDTH] = [[2, 1, 1], [1, 2, 1], [1, 1, 2]];

pub fn hash_pair(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut state = [Goldilocks::zero(); WIDTH];
    state[0] = pack_bytes(left);
    state[1] = pack_bytes(right);
    state[2] = Goldilocks::one();
    poseidon_permute(&mut state);
    let mut out = [0u8; 32];
    for (i, limb) in state.iter().enumerate() {
        out[i * 8..(i + 1) * 8].copy_from_slice(&limb.to_bytes());
    }
    poseidon_permute(&mut state);
    out[24..32].copy_from_slice(&state[0].to_bytes());
    out
}

pub fn hash_leaf(input: &[u8; 32]) -> [u8; 32] {
    hash_pair(input, &EMPTY)
}

const EMPTY: [u8; 32] = [0u8; 32];

fn poseidon_permute(state: &mut [Goldilocks; WIDTH]) {
    for r in 0..ROUNDS {
        for i in 0..WIDTH {
            state[i] = state[i].add(Goldilocks::from_word(ROUND_CONSTANTS[r][i]));
            state[i] = state[i].pow5();
        }
        let mut new_state = [Goldilocks::zero(); WIDTH];
        for i in 0..WIDTH {
            let mut acc = Goldilocks::zero();
            for j in 0..WIDTH {
                acc = acc.add(state[j].mul(Goldilocks::from_word(MDS[i][j])));
            }
            new_state[i] = acc;
        }
        *state = new_state;
    }
}

fn pack_bytes(data: &[u8; 32]) -> Goldilocks {
    let mut acc = Goldilocks::zero();
    let mut chunk = [0u8; 8];
    for i in 0..4 {
        let start = i * 8;
        chunk.copy_from_slice(&data[start..start + 8]);
        acc = acc.add(Goldilocks::from_word(u64::from_le_bytes(chunk)));
    }
    acc
}

#[derive(Clone, Copy)]
struct Goldilocks(u64);

impl Goldilocks {
    const MODULUS: u64 = 0xffffffff00000001;

    fn zero() -> Self {
        Goldilocks(0)
    }

    fn one() -> Self {
        Goldilocks(1)
    }

    fn from_word(value: u64) -> Self {
        Goldilocks(reduce_u128(value as u128))
    }

    fn add(self, rhs: Self) -> Self {
        Goldilocks(reduce_u128(self.0 as u128 + rhs.0 as u128))
    }

    fn mul(self, rhs: Self) -> Self {
        Goldilocks(reduce_u128((self.0 as u128) * (rhs.0 as u128)))
    }

    fn pow5(self) -> Self {
        let x2 = self.mul(self);
        let x4 = x2.mul(x2);
        x4.mul(self)
    }

    fn to_bytes(self) -> [u8; 8] {
        self.0.to_le_bytes()
    }
}

fn reduce_u128(x: u128) -> u64 {
    let low = x as u64;
    let high = (x >> 64) as u64;
    let combined = (low as u128).wrapping_add(((high as u128) << 32).wrapping_sub(high as u128));
    let low = combined as u64;
    let high = (combined >> 64) as u64;
    let combined = (low as u128).wrapping_add(((high as u128) << 32).wrapping_sub(high as u128));
    reduce_u64(combined as u64)
}

fn reduce_u64(x: u64) -> u64 {
    let (reduced, borrow) = x.overflowing_sub(Goldilocks::MODULUS);
    let choice = Choice::from((!borrow) as u8);
    u64::conditional_select(&x, &reduced, choice)
}
