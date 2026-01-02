//! Обёртка HAL для STM32: использует универсальные трейты и даёт возможность подменять драйверы.
use crate::identity::entropy::EntropySource;
use crate::platform::hal::{Hal, MonotonicTimer};
use crate::platform::network::{NetworkStack, NullNetwork};

/// Гибкий HAL для STM32: можно прокинуть любые драйверы таймера/сети.
pub struct Stm32Hal<E, T, N = NullNetwork> {
    entropy: E,
    timer: T,
    network: N,
}

impl<E, T> Stm32Hal<E, T, NullNetwork> {
    /// Создаёт HAL из энтропийного источника и таймера.
    pub const fn new(entropy: E, timer: T) -> Self {
        Self {
            entropy,
            timer,
            network: NullNetwork,
        }
    }

    /// Подключает сетевой стек (например, smoltcp + Ethernet MAC).
    pub fn with_network<N2>(self, network: N2) -> Stm32Hal<E, T, N2> {
        Stm32Hal {
            entropy: self.entropy,
            timer: self.timer,
            network,
        }
    }
}

impl<E, T, N> Hal for Stm32Hal<E, T, N>
where
    E: EntropySource,
    T: MonotonicTimer,
    N: NetworkStack,
{
    type Entropy = E;
    type Timer = T;
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
