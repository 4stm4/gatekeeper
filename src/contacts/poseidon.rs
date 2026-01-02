const FIELD: u64 = 0xffffffff00000001;
const WIDTH: usize = 3;
const ROUNDS: usize = 8;

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

#[inline(always)]
fn add_mod(a: u64, b: u64) -> u64 {
    let (res, carry) = a.overflowing_add(b);
    if carry || res >= FIELD {
        res.wrapping_sub(FIELD)
    } else {
        res
    }
}

#[inline(always)]
fn mul_mod(a: u64, b: u64) -> u64 {
    let res = (a as u128 * b as u128) % (FIELD as u128);
    res as u64
}

fn pow5(x: u64) -> u64 {
    let x2 = mul_mod(x, x);
    let x4 = mul_mod(x2, x2);
    mul_mod(x4, x)
}

fn pack_bytes(data: &[u8; 32]) -> u64 {
    let mut acc = 0u64;
    for block in 0..4 {
        let mut word = 0u64;
        for i in 0..8 {
            let idx = block * 8 + i;
            word |= (data[idx] as u64) << (i * 8);
        }
        acc = acc.wrapping_add(word);
    }
    acc % FIELD
}

fn poseidon_permute(state: &mut [u64; WIDTH]) {
    for r in 0..ROUNDS {
        for i in 0..WIDTH {
            state[i] = add_mod(state[i], ROUND_CONSTANTS[r][i]);
            state[i] = pow5(state[i]);
        }

        let mut new_state = [0u64; WIDTH];
        for i in 0..WIDTH {
            for j in 0..WIDTH {
                let prod = mul_mod(MDS[i][j], state[j]);
                new_state[i] = add_mod(new_state[i], prod);
            }
        }
        *state = new_state;
    }
}

pub fn hash_pair(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut state = [0u64; WIDTH];
    state[0] = pack_bytes(left);
    state[1] = pack_bytes(right);
    state[2] = 1;
    poseidon_permute(&mut state);
    let mut out = [0u8; 32];
    for (i, chunk) in state.iter().enumerate() {
        let bytes = chunk.to_le_bytes();
        out[i * 8..(i + 1) * 8].copy_from_slice(&bytes);
    }
    out
}

pub fn hash_leaf(input: &[u8; 32]) -> [u8; 32] {
    hash_pair(input, &EMPTY)
}

const EMPTY: [u8; 32] = [0u8; 32];
