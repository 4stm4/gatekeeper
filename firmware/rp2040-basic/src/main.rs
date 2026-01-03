#![no_std]
#![no_main]

use embedded_hal::blocking::delay::DelayMs;
use embedded_hal::digital::v2::OutputPin;
use panic_halt as _;
use rp2040_hal::{pac, sio::Sio, watchdog::Watchdog, Timer};
use zk_gatekeeper::identity::init::init_identity;
use zk_gatekeeper::identity::types::DeviceId;
use zk_gatekeeper::platform::alloc::EmbeddedHeap;
use zk_gatekeeper::platform::rp2040::Rp2040Entropy;
use zk_gatekeeper::storage::flash::FlashStorage;

const XOSC_CRYSTAL_FREQ: u32 = 12_000_000;

static mut HEAP: [u8; 32 * 1024] = [0; 32 * 1024];

#[rp2040_hal::entry]
fn main() -> ! {
    unsafe {
        EmbeddedHeap::init(&mut HEAP);
    }

    let mut pac = pac::Peripherals::take().unwrap();
    let mut watchdog = Watchdog::new(pac.WATCHDOG);
    let clocks = rp2040_hal::clocks::init_clocks_and_plls(
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

    let mut led = pins.gpio25.into_push_pull_output();
    let mut timer = Timer::new(pac.TIMER, &mut pac.RESETS, &clocks);

    let mut entropy = Rp2040Entropy;
    let device_id = DeviceId(*b"rp2040-example!!");
    let identity = init_identity(&mut entropy, device_id).expect("identity init failed");

    let flash = FlashStorage::new();
    flash.seal(&identity).expect("seal failed");

    loop {
        let _ = led.set_high();
        timer.delay_ms(150);
        let _ = led.set_low();
        timer.delay_ms(150);
    }
}
