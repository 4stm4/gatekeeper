# Примеры

В каталоге `examples/` собраны минимальные сценарии, показывающие, как использовать подсистемы Gatekeeper как на хосте, так и на RP2040. Все примеры запускаются командой `cargo run --example <имя>`, а для сборки под железо нужно добавить `--target thumbv6m-none-eabi` и соответствующие фичи.

## Host-примеры

| Имя | Описание | Команда |
| --- | --- | --- |
| `identity_roundtrip` | Генерация личности с `DummyEntropy`, вывод `IdentityIdentifier`, выполнение ZK-доказательства. Полезно для smoke-теста API без железа. | `cargo run --example identity_roundtrip` |
| `zk_roundtrip` | Prover и verifier на одном хосте: моделирует полноценный протокол Schnorr с `ChallengeTracker`. | `cargo run --example zk_roundtrip` |

## RP2040: базовый сценарий

`rp2040_basic.rs` демонстрирует полный цикл на железе: инициализация клоков, запуск `Rp2040Entropy`, выпуск личности для `DeviceId(*b"rp2040-example!!")`, опциональный `FlashStorage::seal`, мигание LED.

### Сборка и прошивка

1. Установите цель: `rustup target add thumbv6m-none-eabi`.
2. Соберите пример:  
   ```bash
   cargo run --release --example rp2040_basic \
       --target thumbv6m-none-eabi \
       --features "rp2040-hal embedded-alloc flash-storage"
   ```
   Флаг `embedded-alloc` выделяет глобальный аллокатор (см. пример). Если не планируете использовать Flash, можно убрать `flash-storage`.
3. Для запуска/прошивки используйте `probe-rs run` (поставляется с `cargo run` выше) или явно:  
   `probe-rs run --chip RP2040 target/thumbv6m-none-eabi/release/examples/rp2040_basic`

## RP2040 + RTIC

`rtic_tasks.rs` содержит RTIC-приложение с period task, отправляющей идентификатор по UDP через `SmoltcpNetwork`. Пример компилируется только при `--features rtic-demo`.

Сборка и запуск:

```bash
cargo run --release --example rtic_tasks \
    --features "rtic-demo embedded-alloc flash-storage" \
    --target thumbv6m-none-eabi
```

RTIC требует `panic_halt`, который уже подтягивается примером.

## RP2040 + Embassy

`embassy_async.rs` демонстрирует асинхронную обработку с Embassy executor (таймеры, задачи). Включите флаг `embassy-demo`:

```bash
cargo run --release --example embassy_async \
    --features "embassy-demo embedded-alloc flash-storage" \
    --target thumbv6m-none-eabi
```

## Полезные советы

- Перед прошивкой убедитесь, что `probe-rs` видит отладчик (`probe-rs list`).
- Для уменьшения размера прошивки держите `--release` и профиль из `Cargo.toml` (`opt-level = "z"`, `lto = true`).
- Если нужен только RAM режим (без Flash), удалите `flash-storage` фичу; примеры сами проверяют наличие.
- На host-цели можно исследовать вывод без функционала RP2040 — просто запускайте `cargo run --example …` без `--target`.

При добавлении новых примеров обновляйте таблицу выше, указывая фичи и команды сборки.
