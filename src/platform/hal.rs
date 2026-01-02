//! Унифицированный HAL-слой для разных чипов.
use core::cell::Cell;

use crate::identity::entropy::EntropySource;
use crate::platform::network::{NetworkStack, NullNetwork};
use crate::platform::rp2040::{Rp2040Entropy, Rp2040Timer};

/// Монотонный таймер, использующийся во всех подсистемах.
pub trait MonotonicTimer {
    fn now(&self) -> u64;
    fn delay_ms(&mut self, ms: u32);
}

/// Общий контракт HAL.
pub trait Hal {
    type Entropy: EntropySource;
    type Timer: MonotonicTimer;
    type Network: NetworkStack;

    fn entropy(&mut self) -> &mut Self::Entropy;
    fn timer(&mut self) -> &mut Self::Timer;
    fn network(&mut self) -> &mut Self::Network;
}

/// Простой программный таймер (для тестов/хоста).
pub struct SoftwareTimer {
    ticks: Cell<u64>,
}

impl SoftwareTimer {
    pub const fn new() -> Self {
        Self {
            ticks: Cell::new(0),
        }
    }

    pub fn advance(&self, delta_ms: u64) {
        self.ticks.set(self.ticks.get() + delta_ms);
    }
}

impl MonotonicTimer for SoftwareTimer {
    fn now(&self) -> u64 {
        self.ticks.get()
    }

    fn delay_ms(&mut self, ms: u32) {
        self.advance(ms as u64);
    }
}

/// HAL для RP2040 (по умолчанию с NullNetwork, но можно заменить).
pub struct Rp2040Hal<N: NetworkStack = NullNetwork> {
    entropy: Rp2040Entropy,
    timer: Rp2040Timer,
    network: N,
}

impl<N: NetworkStack> Hal for Rp2040Hal<N> {
    type Entropy = Rp2040Entropy;
    type Timer = Rp2040Timer;
    type Network = N;

    fn entropy(&mut self) -> &mut Self::Entropy {
        &mut self.entropy
    }

    fn timer(&mut self) -> &mut Self::Timer {
        &mut self.timer
    }

    fn network(&mut self) -> &mut Self::Network {
        &mut self.network
    }
}

impl Default for Rp2040Hal<NullNetwork> {
    fn default() -> Self {
        Self::new_with_network(NullNetwork)
    }
}

impl<N: NetworkStack> Rp2040Hal<N> {
    pub fn new_with_network(network: N) -> Self {
        Self {
            entropy: Rp2040Entropy,
            timer: Rp2040Timer::new(),
            network,
        }
    }
}

impl Rp2040Hal<NullNetwork> {
    pub fn with_network<N2: NetworkStack>(self, network: N2) -> Rp2040Hal<N2> {
        Rp2040Hal {
            entropy: self.entropy,
            timer: self.timer,
            network,
        }
    }
}

impl MonotonicTimer for Rp2040Timer {
    fn now(&self) -> u64 {
        self.now_ticks()
    }

    fn delay_ms(&mut self, ms: u32) {
        for _ in 0..ms {
            self.delay_us(1_000);
        }
    }
}
