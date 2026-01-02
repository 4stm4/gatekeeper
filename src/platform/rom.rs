use core::mem;
use core::ptr;

const FUNC_TABLE: *const u16 = 0x0000_0014 as *const u16;
const ROM_TABLE_LOOKUP_PTR: *const u16 = 0x0000_0018 as *const u16;

pub unsafe fn flash_exit_xip() {
    call_void(*b"EX");
}

pub unsafe fn flash_enter_cmd_xip() {
    call_void(*b"CX");
}

pub unsafe fn flash_flush_cache() {
    call_void(*b"FC");
}

pub unsafe fn connect_internal_flash() {
    call_void(*b"IF");
}

pub unsafe fn flash_range_erase(
    addr: u32,
    count: usize,
    block_size: u32,
    block_cmd: u8,
) {
    let func = lookup(*b"RE");
    let erase: extern "C" fn(u32, usize, u32, u8) = mem::transmute(func);
    erase(addr, count, block_size, block_cmd);
}

pub unsafe fn flash_range_program(addr: u32, data: *const u8, count: usize) {
    let func = lookup(*b"RP");
    let program: extern "C" fn(u32, *const u8, usize) = mem::transmute(func);
    program(addr, data, count);
}

pub unsafe fn flash_unique_id(buf: &mut [u8; 8]) {
    let func = lookup(*b"UF");
    let unique: extern "C" fn(*mut u8) = mem::transmute(func);
    unique(buf.as_mut_ptr());
}

fn lookup(tag: [u8; 2]) -> *const u32 {
    unsafe {
        let table = rom_hword_as_ptr(FUNC_TABLE);
        let lookup_ptr = rom_hword_as_ptr(ROM_TABLE_LOOKUP_PTR);
        let lookup_fn: extern "C" fn(*const u16, u32) -> *const u32 = mem::transmute(lookup_ptr);
        lookup_fn(table as *const u16, u16::from_le_bytes(tag) as u32)
    }
}

unsafe fn call_void(tag: [u8; 2]) {
    let func = lookup(tag);
    let f: extern "C" fn() = mem::transmute(func);
    f();
}

unsafe fn rom_hword_as_ptr(addr: *const u16) -> *const u32 {
    let value = ptr::read(addr);
    value as *const u32
}
