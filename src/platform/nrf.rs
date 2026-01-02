//! HAL-сборка для чипов Nordic nRF (nRF52/nRF53).
use crate::identity::entropy::EntropySource;
use crate::platform::hal::{Hal, MonotonicTimer};
use crate::platform::network::{NetworkStack, NullNetwork};

/// Гибко-компонентный HAL для nRF.
pub struct NrfHal<E, T, N = NullNetwork> {
    entropy: E,
    timer: T,
    network: N,
}

impl<E, T> NrfHal<E, T, NullNetwork> {
    pub const fn new(entropy: E, timer: T) -> Self {
        Self {
            entropy,
            timer,
            network: NullNetwork,
        }
    }

    pub fn with_network<N2>(self, network: N2) -> NrfHal<E, T, N2> {
        NrfHal {
            entropy: self.entropy,
            timer: self.timer,
            network,
        }
    }
}

impl<E, T, N> Hal for NrfHal<E, T, N>
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
