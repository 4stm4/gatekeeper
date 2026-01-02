# Stack profiling playbook

## Host-level Criterion bench

- `cargo bench --bench stack_profile -- --sample-size 50 --warm-up-time 1` запускает стенд `benches/stack_profile.rs`. Bench выполняет два сценария:
  1. `identity_init_stack` — генерирует состояние через `init_identity`.
  2. `zk_prove_stack` — вызывает `IdentityState::prove_with` с детерминированным challenge.
- Каждый сценарий оборачивается в `stacker::maybe_grow(32 KiB, 128 KiB)` и вычисляет `stacker::remaining_stack()` до/после. Разница печатается в stdout (`peak XX bytes`) и попадает в отчёт `target/criterion`.
- Bench работает только на host (использует `std` и `stacker`) и не требует RP2040. Он гарантирует, что call graph не расходует больше, чем заданный `maybe_grow` red-zone, а значит можно безопасно подбирать лимит для `probe-run`.

## Статический и аппаратный контроль

- Для точных значений по функциям используйте `RUSTFLAGS="-Z emit-stack-sizes" cargo +nightly build --release --target thumbv6m-none-eabi`. После сборки выполните `llvm-readobj --stack-sizes target/thumbv6m-none-eabi/release/libzk_gatekeeper.a | sort -k4 -nr | head`.
- На устройстве используйте `probe-run --chip RP2040 --stack 0x4000 --release --target thumbv6m-none-eabi --example <app>` — `probe-run` остановит выполнение при превышении лимита и покажет фактическое потребление.
- Сочетая bench + статический анализ + `probe-run` можно выявлять регрессии ещё до прошивки: если Criterion показывает рост, проверяйте `.stack_sizes`, затем подтверждайте лимит на железе.
