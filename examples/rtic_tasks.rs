#![cfg_attr(feature = "rtic-demo", no_std)]
#![cfg_attr(feature = "rtic-demo", no_main)]

#[cfg(feature = "rtic-demo")]
use panic_halt as _;

#[cfg(feature = "rtic-demo")]
use zk_gatekeeper::platform::network::{NetworkConfig, NetworkEndpoint, SmoltcpNetwork};

#[cfg(feature = "rtic-demo")]
use zk_gatekeeper::platform::hal::Rp2040Hal;

#[cfg(feature = "rtic-demo")]
use zk_gatekeeper::identity::entropy::DummyEntropy;
#[cfg(feature = "rtic-demo")]
use zk_gatekeeper::identity::init::init_identity;
#[cfg(feature = "rtic-demo")]
use zk_gatekeeper::identity::types::DeviceId;

#[cfg(feature = "rtic-demo")]
#[rtic::app(device = rp2040_hal::pac, peripherals = true)]
mod app {
    use super::*;

    #[shared]
    struct Shared {
        hal: Rp2040Hal<SmoltcpNetwork>,
    }

    #[local]
    struct Local {}

    #[init]
    fn init(_cx: init::Context) -> (Shared, Local, init::Monotonics) {
        let network = SmoltcpNetwork::new(NetworkConfig::default());
        let hal = Rp2040Hal::new_with_network(network);
        generate_identity::spawn().ok();
        (Shared { hal }, Local {}, init::Monotonics())
    }

    #[task(shared = [hal])]
    fn generate_identity(mut ctx: generate_identity::Context) {
        let mut entropy = DummyEntropy;
        let identity = init_identity(&mut entropy, DeviceId([0x34; 16])).unwrap();
        let payload = identity.identifier().as_bytes();
        let endpoint = NetworkEndpoint::ipv4([192, 168, 4, 2], 9999);
        let _ = ctx
            .shared
            .hal
            .network()
            .send_udp(endpoint, payload)
            .map_err(|err| {
                let _ = err;
            });
        ctx.shared.hal.timer().delay_ms(500);
        generate_identity::spawn().ok();
    }
}

#[cfg(not(feature = "rtic-demo"))]
fn main() {
    println!("Enable --features rtic-demo and build for thumbv6m-none-eabi to run this example.");
}
