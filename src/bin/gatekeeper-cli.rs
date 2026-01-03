#![cfg(feature = "cli")]

use anyhow::{anyhow, bail, Result};
use clap::{Parser, Subcommand};
use rand::rngs::OsRng;
use rand::RngCore;
use zk_gatekeeper::identity::seed::SeedPhrase;
use zk_gatekeeper::identity::types::{DeviceId, IdentityState, RootKey};
use zk_gatekeeper::zk::prover::DeterministicSchnorrProver;

/// CLI для работы с ключами Gatekeeper (генерация, вывод PK/ID и proof).
#[derive(Parser)]
#[command(name = "gatekeeper-cli", version, about = "Gatekeeper key helper")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Сгенерировать новый root/device и вывести все артефакты.
    Generate {
        /// Необязательный DeviceId в hex (16 байт).
        #[arg(long)]
        device: Option<String>,
    },
    /// Посчитать публичный ключ и идентификатор для заданных root/device.
    Derive {
        /// Root key в hex (32 байта).
        #[arg(long)]
        root: String,
        /// DeviceId в hex (16 байт).
        #[arg(long)]
        device: String,
    },
    /// Выполнить детерминированное Schnorr-доказательство для challenge.
    Prove {
        /// Root key в hex (32 байта).
        #[arg(long)]
        root: String,
        /// DeviceId в hex (16 байт).
        #[arg(long)]
        device: String,
        /// Challenge в текстовом виде (UTF-8).
        #[arg(long)]
        challenge: String,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Generate { device } => generate(device)?,
        Command::Derive { root, device } => {
            let state = state_from_hex(&root, &device)?;
            print_overview(&state);
        }
        Command::Prove {
            root,
            device,
            challenge,
        } => {
            let state = state_from_hex(&root, &device)?;
            let prover = DeterministicSchnorrProver::default();
            let proof = state
                .prove_with(&prover, challenge.as_bytes())
                .map_err(|err| anyhow!(err))?;
            print_overview(&state);
            println!("proof: {}", hex::encode(proof.as_bytes()));
        }
    }
    Ok(())
}

fn generate(device_override: Option<String>) -> Result<()> {
    let mut rng = OsRng;
    let mut root_bytes = [0u8; 32];
    rng.fill_bytes(&mut root_bytes);
    let mut dev_bytes = [0u8; 16];
    if let Some(hex) = device_override {
        dev_bytes = parse_hex_array(&hex, 16, "device id")?;
    } else {
        rng.fill_bytes(&mut dev_bytes);
    }

    let state = IdentityState::from_root(RootKey::from_bytes(root_bytes), DeviceId(dev_bytes))
        .map_err(|err| anyhow!(err))?;
    let seed = SeedPhrase::from_root(state.root_key());

    println!("root_key: {}", hex::encode(root_bytes));
    print_overview(&state);
    println!("seed_phrase: {}", seed.words().join(" "));
    Ok(())
}

fn state_from_hex(root: &str, device: &str) -> Result<IdentityState> {
    let root_bytes = parse_hex_array(root, 32, "root key")?;
    let device_bytes = parse_hex_array(device, 16, "device id")?;
    IdentityState::from_root(RootKey::from_bytes(root_bytes), DeviceId(device_bytes))
        .map_err(|err| anyhow!(err))
}

fn print_overview(state: &IdentityState) {
    let device_hex = hex::encode(state.device_id().0);
    let pk_hex = hex::encode(state.public_key().as_bytes());
    let identifier_hex = hex::encode(state.identifier().as_bytes());
    println!("device_id: {}", device_hex);
    println!("public_key: {}", pk_hex);
    println!("identifier: {}", identifier_hex);
}

fn parse_hex_array<const N: usize>(
    input: &str,
    expected_len: usize,
    label: &str,
) -> Result<[u8; N]> {
    let mut cleaned = String::with_capacity(input.len());
    for ch in input.trim().chars() {
        if ch == ' ' || ch == '_' {
            continue;
        }
        cleaned.push(ch);
    }
    if let Some(stripped) = cleaned.strip_prefix("0x") {
        cleaned = stripped.to_string();
    }
    if cleaned.len() != expected_len * 2 {
        bail!("{} must contain {} hex chars", label, expected_len * 2);
    }
    let mut out = [0u8; N];
    hex::decode_to_slice(cleaned, &mut out).map_err(|_| anyhow!("invalid hex for {}", label))?;
    Ok(out)
}
