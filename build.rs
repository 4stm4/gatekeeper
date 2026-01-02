use std::env;
use std::error::Error;
use std::fs;
use std::path::PathBuf;

const FLASH_TOTAL_SIZE: usize = 2 * 1024 * 1024;
const FLASH_SECTOR_SIZE: usize = 4096;

fn main() {
    println!("cargo:rerun-if-changed=memory.x");
    println!("cargo:rerun-if-env-changed=ZK_BOOTLOADER_BYTES");
    println!("cargo:rerun-if-env-changed=ZK_STORAGE_SECTORS");
    if let Err(err) = generate_flash_layout() {
        panic!("flash layout generation failed: {err}");
    }
}

fn generate_flash_layout() -> Result<(), Box<dyn Error>> {
    let bootloader = parse_env("ZK_BOOTLOADER_BYTES")?.unwrap_or(0x1000);
    let storage_sectors = parse_env("ZK_STORAGE_SECTORS")?.unwrap_or(4);
    if storage_sectors == 0 {
        return Err("ZK_STORAGE_SECTORS must be > 0".into());
    }

    let storage_size = storage_sectors * FLASH_SECTOR_SIZE;
    let storage_offset = FLASH_TOTAL_SIZE
        .checked_sub(storage_size)
        .ok_or("storage region exceeds flash size")?;

    if storage_offset <= bootloader {
        return Err(format!(
            "storage offset 0x{storage_offset:08X} overlaps bootloader reservation 0x{bootloader:08X}"
        )
        .into());
    }

    let out_dir = PathBuf::from(env::var("OUT_DIR")?);
    let layout_path = out_dir.join("flash_layout.rs");
    let contents = format!(
        "pub const FLASH_STORAGE_SECTORS_CFG: usize = {storage_sectors};\n\
         pub const FLASH_STORAGE_OFFSET_CFG: usize = {storage_offset};\n\
         pub const BOOTLOADER_RESERVE_CFG: usize = {bootloader};\n"
    );
    fs::write(layout_path, contents)?;
    Ok(())
}

fn parse_env(name: &str) -> Result<Option<usize>, Box<dyn Error>> {
    match env::var(name) {
        Ok(val) => {
            let trimmed = val.trim();
            if trimmed.is_empty() {
                return Ok(None);
            }

            let parsed = if let Some(rest) = trimmed.strip_prefix("0x") {
                usize::from_str_radix(rest, 16)?
            } else {
                trimmed.parse()?
            };
            Ok(Some(parsed))
        }
        Err(env::VarError::NotPresent) => Ok(None),
        Err(other) => Err(Box::new(other)),
    }
}
