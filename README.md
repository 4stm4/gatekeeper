# zk-gatekeeper

Experimental `no_std` identity and ZK helper crate for RP2040 deployments.

## Feature flags и контроль зависимостей

- По умолчанию включены флаги `flash-storage`, `secure-storage`, `storage-gate`, `contacts`, `handshake`, `network`, `logging`. Их можно отключить через `--no-default-features` и включать выборочно:  
  - `flash-storage` — базовый драйвер Flash + `identity::persist`.  
  - `secure-storage` — WAL/SQLCipher‑подобное хранилище.  
  - `storage-gate` — Blob Access Gate.  
  - `contacts` — Merkle дерево контактов.  
  - `handshake` — Noise IK + Double Ratchet (подтягивает опциональный `x25519-dalek`).  
  - `network` — smoltcp-транспорт (Loopback + UDP/TCP и вспомогательные абстракции).  
  - `logging` — включает макросы логирования (`zk_log_*`), которые проксируют в `log`. При отключении весь вывод вырезается компилятором.
  - `embedded-alloc` — подключает `embedded_alloc::Heap` как `#[global_allocator]`. Требует вызова `platform::alloc::EmbeddedHeap::init(&mut BUFFER)` из `static mut`-буфера.
- Все остальные зависимости (`curve25519-dalek`, `sha2`, `hmac`) остаются в ядре, но `curve25519-dalek` собирается с `precomputed_tables`, что уменьшает количество повторных умножений и ускоряет prove()/verify без роста RAM.
- Для демонстрационных RTIC/Embassy задач предусмотрены опциональные флаги `rtic-demo` и `embassy-demo`, которые добавляют соответствующие зависимости только для примеров.

## Примеры

- `examples/identity_roundtrip.rs`/`zk_roundtrip.rs` — host-примеры с DummyEntropy и печатью proof.
- `examples/rp2040_basic.rs` — минимальный старт на RP2040: инициализация клоков, запуск `Rp2040Entropy`, генерация личности и (опционально) `FlashStorage::seal`, плюс мигание LED. Сборка:  
  `cargo run --release --example rp2040_basic --target thumbv6m-none-eabi --features rp2040-hal[,embedded-alloc]`
- `examples/rtic_tasks.rs`, `examples/embassy_async.rs` скомпилируются только при включении соответствующих флагов (`rtic-demo`/`embassy-demo`).

## Аллокатор для embedded

- Если необходимы `Vec`/`Box` в `#![no_std]` режиме, включите `--features embedded-alloc` и выделите статический буфер:  
  ```rust,ignore
  #[cfg(feature = "embedded-alloc")]
  static mut HEAP: [u8; 32 * 1024] = [0; 32 * 1024];

  #[cfg(feature = "embedded-alloc")]
  unsafe {
      zk_gatekeeper::platform::alloc::EmbeddedHeap::init(&mut HEAP);
  }
  ```  
  Без этой инициализации любые вызовы `Vec::push` приведут к panic.

## Модель угроз

- Краткое изложение сценариев, атакующих и мер защиты находится в `docs/threat_model.md`. Документ описывает границы доверия, защиту от физических атак, replay, угрозы Flash и ограничения платформы.

## Модель личности

- **Публичный ключ** вычисляется детерминированно: `PK = sk_user · G`. Ключ не хранится в Flash, но доступен через `IdentityState::public_key()`.
- **Идентификатор личности** — это `IdentityIdentifier = SHA256("zk-gatekeeper-identity" || PK)`. Он стабильный и публичный, поэтому именно его рекомендуемые хранить verifier'у для линковки устройств. Два proof считаются принадлежащими одной личности тогда, когда совпадает `IdentityIdentifier`. Новое устройство с другим `sk_user` → другой `PK` → другой идентификатор.
- `IdentityState::identifier()` возвращает готовое значение, а на стороне проверки `IdentityIdentifier::matches(public_key)` гарантирует, что предъявленный `PK` действительно принадлежит ожидаемой личности.
- В sealed-пакет вместе с секретом сохраняется и `pk_user` (в зашифрованном payload), что позволяет быстро проверить целостность данных при восстановлении.

## Device linking

- Базовая модель: один `root_key`, разные `device_id`, разные `sk_device = HKDF(root_key, device_id)`. API `IdentityState::from_root` и `DeviceEnrollment::from_root` позволяют восстановить/создать состояние для нового устройства, не раскрывая `root_key` третьим сторонам.
- `IdentityState::enroll_device` генерирует пакет с `sk_device`, `pk_device` и `identity_identifier`, готовый к передаче новому устройству (по защищённому каналу).
- `RevocationRegistry` предоставляет минимальный механизм отзыва устройств: регистрация `device_id`, проверка `is_revoked` и явная ошибка при переполнении списка.
- Все HKDF-вызовы используют явные контекстные строки (`hkdf:user-key-v1`, `hkdf:storage-key-v1`), поэтому материалы для identity и storage никак не пересекаются даже при одинаковых `root_key`/`device_id`.

## Seed-фраза и восстановление

- Seed-фраза формируется из 34 слов словаря Gatekeeper (`gate000`…`gate255`). Первые 32 слова кодируют `root_key`, последние 2 — checksum SHA-256.
- `SeedPhrase::from_root`/`::words` создают мнемонику при «цифровом рождении», `SeedPhrase::from_slice`/`recover_root` — гарантируют детерминированное восстановление и проверку корректности.
- `init_identity_with_seed` возвращает пару `(IdentityState, SeedPhrase)`, а `recover_identity_from_seed` создаёт состояние для любого `device_id` без обращения к энтропии.

## HAL-уровень и мульти-чип

- `platform::hal` задаёт единый контракт `Hal` + `MonotonicTimer`: любой чип обязан предоставить источник энтропии, монотонный таймер и сетевой стек. Это позволяет переносить Identity Manager на STM32, nRF и др. без переписывания верхнего уровня.
- `platform::hal::Rp2040Hal` связывает `Rp2040Entropy`, `Rp2040Timer` и любой `NetworkStack`. Для STM32 и nRF доступны обёртки `platform::stm32::Stm32Hal` и `platform::nrf::NrfHal`, куда можно передавать реальные драйверы (HAL из экосистемы `stm32-rs`, `nrf-hal` и т. д.).
- `Rp2040Timer` теперь публичный и реализует `MonotonicTimer`, поэтому ZK/handshake подсистемы используют единый источник времени, а RTIC/Embassy задачи могут читать таймстемпы/делеи через HAL.

## Сетевой транспорт (UDP/TCP)

- `platform::network` экспортирует `NetworkStack` с операциями `send_udp/recv_udp/connect_tcp` и базовую реализацию `SmoltcpNetwork` (Loopback + TCP/UDP сокеты). Конфигурация задаётся через `NetworkConfig` (MAC, IP, размер буферов).
- Для устройств без сети существует `NetworkStack`-заглушка `NullNetwork`, но при включённом флаге `network` можно переключиться на smoltcp (или собственный драйвер) одним вызовом `Hal::with_network`.
- Сетевой слой выдаёт `IdentityError::NetworkUnavailable`/`NetworkStackError` при любых проблемах, поэтому вызовы `seal_identity()` и обмена сообщениями могут одинаково реагировать на сбои транспорта.

## Энтропия и стойкость

- Источник энтропии `platform::rp2040::Rp2040Entropy` собирает шум сразу из нескольких аппаратных доменов: джиттер ROSC (`ROSC_RANDOMBIT`), дрожание таймера (`timer_raw`) и шум чтения SRAM. Каждый байт строится итеративным смешиванием (XOR/вращения) нескольких выборок, а при недоступности ROSC/таймера возвращается `IdentityError::EntropyUnavailable`.
- Для тестирования и failover добавлены `identity::entropy::{MockEntropy, PseudoEntropy, FallbackEntropy}`: `MockEntropy` детерминированно воспроизводит буфер и может эмулировать полный отказ источника, `PseudoEntropy` — лёгкий потоковый ГПСЧ на SHA-256 (без heap), а `FallbackEntropy` автоматически переключается на него при `EntropyUnavailable`. Это покрывается `tests/entropy.rs`.
- В prove/verify используется синхронная детерминированная схема Schnorr: nonce = H("nonce" || domain || challenge || sk), поэтому RNG не нужен, а повторный challenge даёт тот же proof (контролирует verifier). Все временные скаляры и буферы очищаются `zeroize` (см. `identity::keys`, `zk::prover`, `zk::proof`, `storage::flash`), что исключает утечки через RAM.
- Код избегает ветвлений по секретным данным: все проверки `if` завязаны только на публичные условия (challenge длина, доступность ROSC, проверка MAC).
- Поле Goldilocks для Poseidon, сравнение `derived_pk` и прочие операции с ключами выполняются в постоянное время (`subtle`, `Scalar::mul_add`), поэтому тайминговые атаки на `sk_user` и производные ключи бессмысленны.

## Защита от повторов (replay)

- **Verifier** обязан генерировать уникальные challenge и регистрировать их перед отправкой (`zk::verifier::ChallengeTracker::register(challenge, now_ticks)`), указывая текущий монотонный таймер. После получения proof challenge должен быть потреблён через `Verifier::verify(..., now_ticks, proof)`, что блокирует его повторное использование.
- `ChallengeTrackerConfig { capacity, ttl_ticks }` задаёт лимит хранилища и TTL. Старые challenge автоматически вычищаются по TTL, а при переполнении применяется LRU-эвикция, поэтому host может безопасно выставлять большое время жизни и динамически управлять объёмом памяти без пересборок.
- **Prover** никогда не кэширует доказательства и не отвечает на пустые либо слишком длинные challenge (см. `DeterministicSchnorrProver::prove` и проверки в `ZkProof::verify`). Повторный challenge детерминированно даёт тот же proof, поэтому именно verifier несёт ответственность за одноразовость значений.
- Если challenge не был зарегистрирован или уже использован, `ChallengeTracker` вернёт `IdentityError::ChallengeNotRegistered` / `ReplayDetected`, и proof отвергнется до криптографической проверки.

## Политика очистки памяти

- Все временные скаляры в криптографических операциях обнуляются через `zeroize` перед выходом (`identity::keys`, `zk::prover`, `zk::proof`).
- В `storage::flash::seal` и `unseal` после каждого шага очищаются временные буферы (ciphertext, ключи, MAC, читаемые заголовки). Это гарантирует, что в RAM не останется корневых ключей после завершения операций.
- Новые API не возвращают ссылки на `sk_user`, а `IdentityState::prove_with` лишь на время жизни вызова создаёт `ZkSecretRef`. Это исключает зависание секретов в структурах верхнего уровня.

## Логирование

- Критические участки (`storage::flash`, `zk::verifier`) используют прокси-макросы `zk_log_info!/warn!/debug!`, которые при включённом флаге `logging` перенаправляются в `log`. Это позволяет подключить ITM/RTT/host-bridge, сохраняя `no_std`.
- При отключении флага `logging` макросы компилируются в no-op, что уменьшает размер бинарника и исключает зависимость от `log::Log`. Встраиваемые проекты всё равно могут предоставить собственный `log::Log` (например, через `defmt` bridge) и оставить вывод включённым.

## Физические атаки и secure boot

- Состояние во Flash привязано к конкретному RP2040: `storage::flash` смешивает (`DeviceBindingKey::mix_into`) ключи шифрования/MAC с аппаратным `DeviceUid`, извлечённым через ROM (`flash_unique_id`). Даже если атакующий скопирует Flash в другой чип, данные останутся непригодными без UID/PUF исходного устройства.
- Secure boot проверяется перед `unseal`: `platform::secure_boot::{FirmwareRegion,FirmwareGuard}` вычисляют SHA-256 образа XIP-Flash и возвращают `IdentityError::SecureBootFailure`, если hash не совпадает. Встроенный helper `identity::persist::unseal_identity_guarded` обязует вызывающего предоставить контрольную сумму и тем самым блокирует загрузку личности при подмене прошивки.
- Секреты (`sk_user`, master-key LittleFS) никогда не лежат в открытом виде в LittleFS/Flash: модуль `platform::secure_vault` пишет их в отдельный сектор, зашифрованный ключом PUF (`DeviceBindingKey`). Дамп Flash или SWD не раскрывает содержимое без доступа к конкретному кристаллу.
- Угрозы физического доступа документируются явно: этот README фиксирует сценарии (чтение RAM/Flash, перенос образа на другое устройство, подмена прошивки) и ответные меры (zeroization, device binding, secure boot).

## Эталонная проверка proof

### ZK statement и формат

- ZK-утверждение: «Существует скаляр `sk_user`, такой что `PK = sk_user · G` и `s·G = R + H(domain, challenge, PK, R) · PK`, где `(R, s)` получены от prover». Реализация повторяет детерминированный Schnorr с Fiat–Shamir.
- Domain separation: все хэши включают префиксы `"nonce"`/`"zk-gatekeeper-v1-challenge"` плюс выбранную строку домена (по умолчанию `b"zk-gatekeeper-schnorr-v1"`). Это исключает смешение с другими протоколами.
- Формат `ZkProof` фиксирован и документирован:  
  ```
  struct ProofV1 {
      version: u8 = 0x01;
      payload_len: u8 = 64; // commitment + response
      commitment: [u8; 32]; // R
      response:   [u8; 32]; // s
  }
  ```
  Сериализованный размер — 66 байт (`ZK_PROOF_LEN`). `payload_len` проверяется при десериализации, что защищает от усечённых сообщений.

### Эталонный verifier и host-суместимость

- Минимальный стек проверки находится в `zk::verifier`:  
  1. `Verifier::new(domain, ChallengeTrackerConfig::new(capacity, ttl_ticks))` фиксирует домен и параметры трекера.  
  2. `verifier.tracker_mut().register(challenge, now_ticks)` — учёт одноразовых challenge и TTL.  
  3. Получив `(proof, PK, IdentityIdentifier)`, вызывайте `verifier.verify(..., now_ticks, proof)`:  
     - Проверяется `IdentityIdentifier::matches(PK)`.  
     - Challenge помечается использованным (LRU/TTL обрабатываются автоматически); повтор вернёт `ReplayDetected`.  
     - `ZkProof::verify` проверит уравнение Schnorr и версию proof.
- Этот код не зависит от RP2040 и может компилироваться в любых host-программах (см. `tests/zk.rs`).

### Host-тесты и совместимость

- В `tests/zk.rs` есть два интеграционных теста: `prover_verifier_roundtrip` (проверяет совместимость формата prover ↔ verifier) и `replay_detected` (убеждается, что повтор proof по тому же challenge даёт ошибку).
- Для проверки совместимости внешних реализаций используйте `ZK_PROOF_VERSION`, `ZK_PROOF_LEN`, `ZK_COMMITMENT_LEN` и `ZK_RESPONSE_LEN` из `zk::proof`. Любое изменение формата потребует обновления версии и тестов.

## Merkle tree контактов

- Контакты представляются как фиксированное Poseidon-дерево глубины 8 (до 256 контактов). Каждая вершина — Poseidon(`left`,`right`), листья — Poseidon(`PK`,`0`). Пустые листья заполнены нулями, так что `contact_set_root` всегда детерминирован.
- Хеш-функция — Poseidon2 над полем Goldilocks (`p = 2^64 - 2^32 + 1`, α = 5, ширина 3) с константами, пригодными для Plonky2/STARK цепочек. Благодаря этому Merkle-путь может напрямую использоваться в ZK-гостях.
- Структуры `contacts::ContactTree` и `ContactWitness` управляют списком контактов: добавление (`add_contact`), удаление/отзыв (`remove_contact`), пересчёт корня и генерация доказательства членства. Дублирующиеся контакты запрещены, переполнение выдаёт `IdentityError::ContactListFull`.
- `contact_set_root()` возвращает текущее значение корня, подходящее для публикации. Оно обновляется при каждом изменении набора.
- Для ZK-проверки членства используйте `ContactTree::membership_proof`, который возвращает `ContactWitness`. Метод `prepare_zk_inputs()` готовит входные данные для гостя: `(root, leaf, siblings[], path_bits[])`, что соответствует statement «мой `PK` находится в твоём дереве контактов».

## Handshake и Double Ratchet

- После успешного ZK-verify устройства выполняют упрощённый Noise IK-подобный обмен на `x25519`: `handshake::initiator_start` формирует первое сообщение (эпемерный ключ + MAC), `handshake::responder_accept` проверяет MAC, генерирует ответ и вычисляет общий секрет. `initiator_finish` завершается после получения ответа. Оба шага используют лишь публичные данные (domain, capability bits) и `EntropySource` для эпемерных ключей.
- Формат `HandshakeMessage`: `version (1)` + `capabilities (u32)` + `ephemeral public key (32 байта)` + `mac (32 байта)`. Все MAC считаются как `HMAC-SHA256(shared_secret, "gatekeeper-noise-mac" || capabilities)`, что фиксирует домен.
- Capability Manager (`handshake::CapabilityFlags/CapabilityManager`) объявляет возможности устройства (VOICE/FILES/TEXT/VIDEO). На выходе обе стороны получают пересечение флагов (например, только VOICE). Эти флаги затем используются при инициализации каналов/функций.
- Итоговый общий секрет поступает в `handshake::RatchetState`, который разворачивает простую Double-Ratchet обвязку: `RatchetState::new(shared_secret, RatchetRole::Initiator/Responder)` → цепочки `send/recv`, обновляемые через HKDF при каждом сообщении (`next_send_key`, `next_recv_key`). Состояние (root key + счётчики) можно сохранять во Flash наряду с другими метаданными.

## Secure storage & sync

- `storage::secure::SecureStore` — мини-«SQLCipher»: хранит таблицы `RatchetStateRow` и `ContactMetadata`, применяет WAL (`WalTransaction`) перед каждым коммитом и использует `SecureCipher` (HMAC‑SHA256 поток + MAC) для шифрования снимков. Все записи WAL маскируются в RAM собственным потоковым ключом, поэтому при power-loss'е в памяти не остаётся открытых `root_key`. При сбое `recover()` переигрывает незавершённый WAL и очищает тени.
- Структура ratchet-state (`RatchetStateRow`) включает `IdentityIdentifier`, ключи цепочек и счётчики. Метаданные контактов (`ContactMetadata`) содержат `IdentityIdentifier`, capability-флаги, `last_seen_epoch` и уровень доверия; это позволяет хранить контактную книжку в том же журнале.
- Для синхронизации с мобильным приложением/хостом вызывайте `SecureStore::snapshot(interface)` — метод возвращает `Result<SecureFrame>`, где `SecureFrame { interface, nonce, payload, mac }` и `nonce` — 64‑битный монотонный счётчик, хранящийся в secure vault (Flash). На принимающей стороне `apply_sync_frame` расшифрует и применит снимок; данные передаются через любой транспорт (UART/USB/SPI) без раскрытия содержимого.
- Payload — детерминированный бинарный формат (`RECORD_VERSION=1`), совместимый с тестами. Благодаря MAC и одноразовым nonce устройство защищено от подмены/повторов, а структура WAL обеспечивает консистентность даже при power-loss.

## Storage Access Gate (offline blobs)

- `storage::gate` реализует анонимный доступ к оффлайн-blob’ам: gate выдаёт `BlobFetchChallenge { blob_id, nonce }`, а устройство формирует `BlobFetchRequest` через `BlobIdentityProver`, используя тот же Schnorr-процедурный каркас, но с доменом `b"zk-gatekeeper-blob-v1"` и challenge = `blob_id || nonce`. Identity не раскрывается на транспортном уровне — gate хранит соответствие `(blob_id, IdentityIdentifier, public_key)` и сверяет proof локально.
- `BlobAccessGate` совместим с P2P-хранилищем (Waku Store и т. п.): запросы содержат минимум метаданных (`blob_id`, `nonce`, `proof`) и могут пересылаться как Waku payload'ы. Gate регистрирует права доступа через `BlobAccessEntry`, делает ревокацию (`revoke`) и возвращает `BlobAccessGrant` при успешной проверке.
- Для интеграции с Waku: узел публикует `blob_id` в качестве темы (`/zk-gatekeeper/blob/<hex>`) и отвечает на fetch-запросы только при получении валидного `BlobFetchRequest`. Challenge можно распространять по side-channel (например, Waku Request/Response или out-of-band), что предотвращает воспроизведение и минимизирует утечки.

## Форматы и API

- **Flash-record v1**: `magic(4="ZKGS") | version(1) | reserved(1) | payload_len(2=64) | counter(4) | reserved(4) | device_id(16) | ciphertext(64: sk_user || pk_user) | mac(32)` — сериализация из `storage::flash`. Несоответствия версий/длины → `IdentityError::StorageVersionMismatch/StorageCorrupted`.

### Wear leveling и ресурс Flash

- Драйвер `storage::flash` продолжает использовать кольцо слотов (по 4 KiB) для sealed-состояния. Каждый `seal()` пишет в новый слот и стирает только его, поэтому суммарный износ распределяется равномерно (≈100 000 циклов на сектор → ≈400 000 циклов на четыре слота).
- Build-script рассчитывает разметку автоматически: `BOOTLOADER_RESERVE_CFG` резервирует начало Flash под бутлоадер, диапазон `[FLASH_FS_OFFSET_CFG, FLASH_STORAGE_OFFSET_CFG)` выделяется под LittleFS, а `FLASH_STORAGE_OFFSET_CFG`..конец Flash остаётся под wear-level слоты `storage::flash`. Параметры можно менять переменными `ZK_BOOTLOADER_BYTES` и `ZK_STORAGE_SECTORS`; ошибки вылетают при пересечении областей или несоответствии выравниванию.

### Раздел LittleFS

- `storage::littlefs` — полноценный драйвер LittleFS поверх ROM API RP2040 (`littlefs2`). Он использует блоки по 4 KiB и кэш 256 байт, поэтому практически не создаёт дополнительных стираний и даёт wear-leveling для произвольных файлов (ratchet-state, WAL, blob'ы и т. д.).
- Раздел начинается с `FLASH_FS_OFFSET_CFG` (сразу после бутлоадера) и содержит `FLASH_FS_BLOCKS_CFG` блоков по 4 KiB. Пока область не отформатирована, `LittleFs::format()` обязан быть вызван один раз, дальше можно монтировать её из RAM/host.
- Пример использования:
  ```rust,no_run
  use littlefs2::io::Write;
  use littlefs2::path::Path;
  use zk_gatekeeper::storage::littlefs::LittleFs;

  let mut fs = LittleFs::new();
  fs.format().ok(); // только при первом запуске
  fs.mount(|mounted| {
      mounted.create_dir_all(Path::from(b"/state"))?;
      mounted.open_file_with_options_and_then(
          |opts| opts.create(true).write(true).truncate(true),
          Path::from(b"/state/ratchet.bin"),
          |file| file.write(b"ratchet snapshot"),
      )
  }).expect("flash I/O failed");
  ```
- Host-инструменты могут монтировать тот же раздел (через `probe-rs` или SWD дамп) и читать/писать файлы LittleFS напрямую — формат полностью совместим с `littlefs2`.
- **ZkProof v1**: `version(1) | payload_len(1=64) | commitment(32) | response(32)` (см. `zk::proof`). Любые расширения требуют увеличения `ZK_PROOF_VERSION`.
- **Public Key**: 32 байта, сжатая точка Ed25519 (`UserPublicKey`). Выдаётся через `IdentityState::public_key()` и используется в verifier/gate.
- API entrypoints: `identity::{init, seed, link, persist}` (включая `unseal_identity_guarded`), `zk::{prover, verifier}`, `handshake::{initiator_start, responder_accept, ratchet}`, `contacts::ContactTree`, `storage::{flash, secure, gate}`, а также `platform::{rp2040, device, secure_boot}`.

## Тесты

### Юнит-тесты

- `tests/identity.rs` – публичный ключ/идентификатор и seed roundtrip.
- `tests/hkdf.rs` – детерминизм HKDF + независимость storage ключей.
- `tests/zk.rs` – prover ↔ verifier + replay.
- `tests/contacts.rs` – Merkle дерево + членство.
- `tests/storage_gate.rs` – blob gate.
- `tests/handshake.rs` – Noise handshake и Ratchet.
- `tests/entropy.rs` – mock-источник и fallback на псевдо-энтропию.

### Интеграционные сценарии

- Устройство ↔ verifier: `tests/zk.rs::prover_verifier_roundtrip`.
- Device linking + восстановление: `tests/identity.rs`.
- Replay атаки: `tests/zk.rs::replay_detected` и `storage::gate::BlobAccessGate::verify`.

Запуск: `cargo test --tests` (host) и `cargo test --target thumbv6m-none-eabi` после установки `thumbv6m-none-eabi`.

## Документация и протоколы

- README описывает форматы (flash-record, proof, handshake), API и workflow. Для диаграмм используйте PlantUML (пример путь `docs/diagrams/handshake.puml`, TODO).
- Для rustdoc доступна встроенная документация с примерами (`cargo doc --no-deps --features "flash-storage contacts handshake secure-storage storage-gate"`). Сгенерированные HTML-файлы лежат в `target/doc/index.html`.
- Workflow `.github/workflows/docs.yml` автоматически собирает `cargo doc --all-features --no-deps`, упаковывает содержимое `target/doc` и публикует его через GitHub Pages (после включения Pages в настройках репозитория).
- `src/lib.rs` экспортирует минимальный API, дополнительные заметки предполагается хранить в `docs/`.

## Docker-окружение

В репозитории есть `Dockerfile`, который разворачивает минимальный образ на базе `rust:1.83-slim`, устанавливает зависимости clang/packaging и подтягивает nightly, чтобы `bindgen` и `cargo +nightly fetch` работали из коробки. Это удобно, если не хочется ставить toolchain на хост.

Быстрый сценарий:

```bash
# соберите образ один раз
docker build -t zk-gatekeeper .

# запустите тесты в контейнере; по умолчанию выполняется host-таргет
docker run --rm -v "$PWD":/work -w /work zk-gatekeeper
```

Команда запуска соответствует `CMD ["cargo", "test", "--tests", "--target", "x86_64-unknown-linux-gnu"]`. Чтобы выполнить другую цель, добавьте её в конце `docker run`:

```bash
docker run --rm -v "$PWD":/work -w /work zk-gatekeeper \
  cargo test --target x86_64-unknown-linux-gnu --lib
```

Образ заранее прогревает `cargo fetch`, поэтому повторные прогоны не качают crates повторно.

## CLI-утилита `gatekeeper-cli`

Для работы с ключами на хосте доступен бинарь `gatekeeper-cli` (собирается при включённом флаге `cli`). Из-за дефолтного `thumbv6m`-таргета команды запускайте с явным указанием host-платформы:

```bash
# генерация нового root/device и вывод seed-фразы
cargo run --target x86_64-apple-darwin --features cli \
  --bin gatekeeper-cli -- generate

# вывод PK/identifier по заданным hex-значениям
cargo run --target x86_64-apple-darwin --features cli \
  --bin gatekeeper-cli -- derive --root <hex64> --device <hex32>

# получение proof для текстового challenge
cargo run --target x86_64-apple-darwin --features cli \
  --bin gatekeeper-cli -- prove \
  --root <hex64> --device <hex32> --challenge "hello-world"
```

`generate` распечатывает корневой ключ (hex), DeviceId, публичный ключ, идентификатор и seed-фразу (34 слова). `derive` и `prove` используют переданные значения и всегда применяют `DeterministicSchnorrProver` с доменом `zk-gatekeeper-schnorr-v1`.

## Примеры

- `cargo run --example identity_roundtrip` — генерация личности, получение идентификатора и формирование proof.
- `cargo run --example zk_roundtrip` — полный цикл prover ↔ verifier с учётом регистрации challenge.
- `cargo run --example rtic_tasks --features rtic-demo --target thumbv6m-none-eabi` — минимальное RTIC-приложение с параллельными задачами, таймером и UDP-логированием.
- `cargo run --example embassy_async --features embassy-demo` — host-совместимая Embassy-петля, которая параллельно отправляет UDP-пакеты и показывает подход к обработке асинхронных событий.

## no_std-аудит и сборка

- Проект `#![no_std]`; зависимости подключены без `std`. Проверяйте `cargo check --no-default-features --target thumbv6m-none-eabi`.
- Размер и зависимост и: `cargo build --release --target thumbv6m-none-eabi` + `cargo size --target thumbv6m-none-eabi --lib`; `cargo tree --edges no-dev`. Те же команды автоматически выполняются в CI (`.github/workflows/size.yml`) — push/PR падает, если `cargo size` не проходит.

## Профилирование стека

- **Статический проход:** `rustup component add llvm-tools-preview` один раз, далее `RUSTFLAGS="-Z emit-stack-sizes" cargo +nightly build --release --target thumbv6m-none-eabi`. Полученные `.stack_sizes` читаются через `llvm-readobj --stack-sizes target/thumbv6m-none-eabi/release/libzk_gatekeeper.a | sort -k4 -nr | head`, что мгновенно показывает пиковые затраты стека на каждую функцию.
- **Runtime на железе:** `probe-run --chip RP2040 --stack 0x4000 target/thumbv6m-none-eabi/release/examples/<app>.elf` останавливает выполнение при выходе за лимит и печатает реальное потребление. Это позволяет проверять каждую сборку после линковки.
- **Host-профилирование:** для нагрузочных сценариев используется `criterion`-бенч (описан в `docs/stack_profiling.md`), который гоняет `init_identity` и `prove()` в цикле и логирует `stacker::remaining_stack()` — так можно подбирать безопасный `probe-run --stack` порог ещё до прошивки.

## Прошивка RP2040 и проверка через system_check

### Сборка и прошивка платы

1. Установите toolchain `xPack ARM GCC` и добавьте его в `$PATH` на время сборки:
   ```bash
   export PATH="$HOME/.local/toolchains/xpack-arm-none-eabi-gcc-14.2.1-1.1/bin:$PATH"
   ```
2. Соберите минимальную прошивку:
   ```bash
   cd firmware/rp2040-basic
   cargo build --release --target thumbv6m-none-eabi
   ```
3. Сконвертируйте ELF в UF2 (требуется `elf2uf2-rs` из crates.io):
   ```bash
   elf2uf2-rs \
     target/thumbv6m-none-eabi/release/rp2040-basic-fw \
     target/thumbv6m-none-eabi/release/rp2040-basic.uf2
   ```
4. Подключите RP2040 в режиме BOOTSEL (удерживая кнопку при подаче питания). Смонтируется флешка `RPI-RP2`. Скопируйте готовый UF2:
   ```bash
   cp target/thumbv6m-none-eabi/release/rp2040-basic.uf2 /Volumes/RPI-RP2/
   ```
   После копирования плата перезагрузится и должна начать мигать LED (пример демонстрирует `init_identity` и `FlashStorage::seal`). Если копирование зависает, извлеките и переподключите устройство и повторите шаг.

### Проверка на хосте

Поскольку `.cargo/config.toml` по умолчанию фиксирует `thumbv6m-none-eabi`, для host-команд всегда указывайте `--target x86_64-apple-darwin` (или другой подходящий).

- Интеграционный пример, который повторяет полный сценарий (генерация личности → доказательство → Noise‑канал):
  ```bash
  cargo run --example system_check --target x86_64-apple-darwin
  ```
  В выводе появятся три «галочки»: proof проверен, capability‑флаги совпали, SecureChannel обменялся сообщениями. Это быстрый sanity-check перед прошивкой.

- Полный набор тестов (unit + integration + doctest) на хосте:
  ```bash
  cargo test --target x86_64-apple-darwin
  ```
  Для embedded‑целей оставляйте `--target thumbv6m-none-eabi` и при необходимости запускайте через `probe-run` или копирование UF2, как описано выше.
