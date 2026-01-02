use core::hint::spin_loop;
use core::ptr::read_volatile;

use crate::error::IdentityError;
use crate::identity::entropy::EntropySource;

pub struct Rp2040Entropy;
pub struct Rp2040Timer;

const ROSC_BASE: usize = 0x4006_0000;
const ROSC_STATUS_OFFSET: usize = 0x18;
const ROSC_RANDOMBIT_OFFSET: usize = 0x1c;
const ROSC_STATUS_STABLE: u32 = 1 << 31;
const ROSC_STATUS_ENABLED: u32 = 1 << 12;

const TIMER_BASE: usize = 0x4005_4000;
const TIMER_RAW_LOW_OFFSET: usize = 0x28;

const SRAM_BASE: usize = 0x2000_0000;
const SRAM_SIZE: usize = 256 * 1024;
const SRAM_MASK: usize = SRAM_SIZE - 4;

const MIX_ROUNDS: usize = 8;
const ROSC_SUBSAMPLES: usize = 4;

#[inline(always)]
fn timer_raw() -> u32 {
    unsafe { read_volatile((TIMER_BASE + TIMER_RAW_LOW_OFFSET) as *const u32) }
}

#[inline(always)]
fn rosc_bit() -> u32 {
    unsafe { read_volatile((ROSC_BASE + ROSC_RANDOMBIT_OFFSET) as *const u32) & 1 }
}

#[inline(always)]
fn sample_sram(seed: u32) -> u32 {
    let offset = ((seed as usize) & SRAM_MASK) & !0x3;
    let ptr = (SRAM_BASE + offset) as *const u32;
    unsafe { read_volatile(ptr) }
}

#[inline(always)]
fn busy_delay(mut ticks: u32) {
    ticks &= 0xff;
    for _ in 0..(ticks + 3) {
        spin_loop();
    }
}

impl Rp2040Entropy {
    fn ensure_rosc_ready() -> Result<(), IdentityError> {
        let status = unsafe { read_volatile((ROSC_BASE + ROSC_STATUS_OFFSET) as *const u32) };
        let mask = ROSC_STATUS_STABLE | ROSC_STATUS_ENABLED;
        if (status & mask) != mask {
            return Err(IdentityError::EntropyUnavailable);
        }
        Ok(())
    }

    fn ensure_timer_running() -> Result<(), IdentityError> {
        let first = timer_raw();
        for _ in 0..128 {
            let now = timer_raw();
            if now != first {
                return Ok(());
            }
            spin_loop();
        }
        Err(IdentityError::EntropyUnavailable)
    }

    fn validate_noise() -> Result<(), IdentityError> {
        let mut last = rosc_bit();
        let mut transitions = 0u32;
        for _ in 0..128 {
            let bit = rosc_bit();
            if bit != last {
                transitions += 1;
            }
            last = bit;
        }
        if transitions < 4 {
            Err(IdentityError::EntropyUnavailable)
        } else {
            Ok(())
        }
    }

    fn mix_round(&mut self, round: usize, state: u32) -> Result<u32, IdentityError> {
        Self::ensure_rosc_ready()?;

        let mut osc = 0u32;
        for shift in 0..ROSC_SUBSAMPLES {
            osc |= rosc_bit() << shift;
            let timer = timer_raw();
            busy_delay(timer ^ (shift as u32));
        }

        let timer_before = timer_raw();
        busy_delay(timer_before.rotate_left((round as u32) & 31));
        let timer_after = timer_raw();
        let delta = timer_after.wrapping_sub(timer_before);

        let sram_seed = delta ^ osc ^ state.rotate_left((round as u32) & 31);
        let mut sram_word = sample_sram(sram_seed);

        let mut combined = state
            ^ osc.rotate_left((((round + 1) * 3) as u32) & 31)
            ^ delta.rotate_right(3)
            ^ sram_word.rotate_left(((round * 5) & 31) as u32);

        let result = combined.rotate_left(7) ^ combined;
        combined = 0;
        sram_word = 0;
        osc = 0;
        Ok(result)
    }

    fn collect_byte(&mut self) -> Result<u8, IdentityError> {
        let mut accum = 0u32;
        for round in 0..MIX_ROUNDS {
            accum = self.mix_round(round, accum)?;
        }

        let folded = accum ^ (accum >> 11) ^ (accum >> 19);
        let byte = (folded & 0xff) as u8;
        accum = 0;
        Ok(byte)
    }
}

impl EntropySource for Rp2040Entropy {
    fn fill_bytes(&mut self, out: &mut [u8]) -> Result<(), IdentityError> {
        if out.is_empty() {
            return Ok(());
        }

        Self::ensure_rosc_ready()?;
        Self::ensure_timer_running()?;
        Self::validate_noise()?;

        for byte in out.iter_mut() {
            *byte = self.collect_byte()?;
        }

        Ok(())
    }
}

impl Rp2040Timer {
    pub const fn new() -> Self {
        Self
    }

    #[inline(always)]
    pub fn now_ticks(&self) -> u64 {
        timer_raw() as u64
    }

    pub fn delay_us(&mut self, micros: u32) {
        let start = timer_raw();
        while timer_raw().wrapping_sub(start) < micros {
            spin_loop();
        }
    }
}
