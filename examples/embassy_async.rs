#![cfg_attr(feature = "embassy-demo", no_std)]
#![cfg_attr(feature = "embassy-demo", no_main)]

#[cfg(feature = "embassy-demo")]
use embassy_executor::Spawner;
#[cfg(feature = "embassy-demo")]
use embassy_time::{Duration, Instant, Timer};
#[cfg(feature = "embassy-demo")]
use static_cell::make_static;
#[cfg(feature = "embassy-demo")]
use zk_gatekeeper::platform::network::{NetworkConfig, NetworkEndpoint, SmoltcpNetwork};

#[cfg(feature = "embassy-demo")]
#[embassy_executor::main]
async fn main(_spawner: Spawner) {
    let network: &'static mut SmoltcpNetwork =
        make_static!(SmoltcpNetwork::new(NetworkConfig::default()));
    loop {
        let now = Instant::now();
        let _ = network.poll(now.as_micros() as i64);
        let payload = now.as_millis().to_le_bytes();
        let endpoint = NetworkEndpoint::ipv4([10, 0, 0, 10], 5050);
        let _ = network.send_udp(endpoint, &payload);
        Timer::after(Duration::from_millis(250)).await;
    }
}

#[cfg(not(feature = "embassy-demo"))]
fn main() {
    println!("Enable --features embassy-demo to build this example.");
}
