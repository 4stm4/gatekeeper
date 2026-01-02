#![cfg_attr(feature = "rp2040-hal", no_std)]
#![cfg_attr(feature = "rp2040-hal", no_main)]

#[cfg(feature = "rp2040-hal")]
use panic_halt as _;

#[cfg(feature = "rp2040-hal")]
use embedded_hal::digital::v2::OutputPin;
#[cfg(feature = "rp2040-hal")]
use rp2040_hal::{pac, sio::Sio, watchdog::Watchdog, Timer};
#[cfg(feature = "rp2040-hal")]
use zk_gatekeeper::identity::init::init_identity;
#[cfg(feature = "rp2040-hal")]
use zk_gatekeeper::identity::types::DeviceId;
#[cfg(feature = "rp2040-hal")]
use zk_gatekeeper::platform::rp2040::Rp2040Entropy;
#[cfg(all(feature = "rp2040-hal", feature = "embedded-alloc"))]
use zk_gatekeeper::platform::alloc::EmbeddedHeap;
#[cfg(all(feature = "rp2040-hal", feature = "flash-storage"))]
use zk_gatekeeper::storage::flash::FlashStorage;

#[cfg(feature = "rp2040-hal")]
const XOSC_CRYSTAL_FREQ: u32 = 12_000_000;

#[cfg(all(feature = "rp2040-hal", feature = "embedded-alloc"))]
static mut HEAP: [u8; 32 * 1024] = [0; 32 * 1024];

#[cfg(feature = "rp2040-hal")]
#[rp2040_hal::entry]
fn main() -> ! {
    #[cfg(feature = "embedded-alloc")]
    unsafe {
        EmbeddedHeap::init(&mut HEAP);
    }

    let mut pac = pac::Peripherals::take().unwrap();
    let mut watchdog = Watchdog::new(pac.WATCHDOG);
    let _clocks = rp2040_hal::clocks::init_clocks_and_plls(
        XOSC_CRYSTAL_FREQ,
        pac.XOSC,
        pac.CLOCKS,
        pac.PLL_SYS,
        pac.PLL_USB,
        &mut pac.RESETS,
        &mut watchdog,
    )
    .ok()
    .unwrap();

    let sio = Sio::new(pac.SIO);
    let pins = rp2040_hal::gpio::Pins::new(
        pac.IO_BANK0,
        pac.PADS_BANK0,
        sio.gpio_bank0,
        &mut pac.RESETS,
    );

    let mut led = pins.led.into_push_pull_output();
    let mut timer = Timer::new(pac.TIMER, &mut pac.RESETS);

    let mut entropy = Rp2040Entropy;
    let device_id = DeviceId(*b"rp2040-example!!");
    let identity = init_identity(&mut entropy, device_id).expect("identity init failed");

    #[cfg(feature = "flash-storage")]
    {
        let flash = FlashStorage::new();
        flash.seal(&identity).expect("seal failed");
    }

    loop {
        let _ = led.set_high();
        timer.delay_ms(150);
        let _ = led.set_low();
        timer.delay_ms(150);
    }
}

#[cfg(not(feature = "rp2040-hal"))]
fn main() {
    println!("Enable --features rp2040-hal to run this example on hardware.");
}
