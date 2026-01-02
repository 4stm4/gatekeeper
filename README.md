# zk-gatekeeper

Experimental `no_std` identity and ZK helper crate for RP2040 deployments.

## Feature flags и контроль зависимостей

- По умолчанию включены флаги `flash-storage`, `secure-storage`, `storage-gate`, `contacts`, `handshake`. Их можно отключить через `--no-default-features` и включать выборочно:  
  - `flash-storage` — базовый драйвер Flash + `identity::persist`.  
  - `secure-storage` — WAL/SQLCipher‑подобное хранилище.  
  - `storage-gate` — Blob Access Gate.  
  - `contacts` — Merkle дерево контактов.  
  - `handshake` — Noise IK + Double Ratchet (подтягивает опциональный `x25519-dalek`).  
- Все остальные зависимости (`curve25519-dalek`, `sha2`, `hmac`) остаются в ядре, но `curve25519-dalek` собирается с `precomputed_tables`, что уменьшает количество повторных умножений и ускоряет prove()/verify без роста RAM.

## Модель личности

- **Публичный ключ** вычисляется детерминированно: `PK = sk_user · G`. Ключ не хранится в Flash, но доступен через `IdentityState::public_key()`.
- **Идентификатор личности** — это `IdentityIdentifier = SHA256("zk-gatekeeper-identity" || PK)`. Он стабильный и публичный, поэтому именно его рекомендуемые хранить verifier'у для линковки устройств. Два proof считаются принадлежащими одной личности тогда, когда совпадает `IdentityIdentifier`. Новое устройство с другим `sk_user` → другой `PK` → другой идентификатор.
- `IdentityState::identifier()` возвращает готовое значение, а на стороне проверки `IdentityIdentifier::matches(public_key)` гарантирует, что предъявленный `PK` действительно принадлежит ожидаемой личности.
- В sealed-пакет вместе с секретом сохраняется и `pk_user` (в зашифрованном payload), что позволяет быстро проверить целостность данных при восстановлении.

## Device linking

- Базовая модель: один `root_key`, разные `device_id`, разные `sk_device = HKDF(root_key, device_id)`. API `IdentityState::from_root` и `DeviceEnrollment::from_root` позволяют восстановить/создать состояние для нового устройства, не раскрывая `root_key` третьим сторонам.
- `IdentityState::enroll_device` генерирует пакет с `sk_device`, `pk_device` и `identity_identifier`, готовый к передаче новому устройству (по защищённому каналу).
- `RevocationRegistry` предоставляет минимальный механизм отзыва устройств: регистрация `device_id`, проверка `is_revoked` и явная ошибка при переполнении списка.

## Seed-фраза и восстановление

- Seed-фраза формируется из 34 слов словаря Gatekeeper (`gate000`…`gate255`). Первые 32 слова кодируют `root_key`, последние 2 — checksum SHA-256.
- `SeedPhrase::from_root`/`::words` создают мнемонику при «цифровом рождении», `SeedPhrase::from_slice`/`recover_root` — гарантируют детерминированное восстановление и проверку корректности.
- `init_identity_with_seed` возвращает пару `(IdentityState, SeedPhrase)`, а `recover_identity_from_seed` создаёт состояние для любого `device_id` без обращения к энтропии.

## Энтропия и стойкость

- Источник энтропии `platform::rp2040::Rp2040Entropy` собирает шум сразу из нескольких аппаратных доменов: джиттер ROSC (`ROSC_RANDOMBIT`), дрожание таймера (`timer_raw`) и шум чтения SRAM. Каждый байт строится итеративным смешиванием (XOR/вращения) нескольких выборок, а при недоступности ROSC/таймера возвращается `IdentityError::EntropyUnavailable`.
- Для тестирования и failover добавлены `identity::entropy::{MockEntropy, PseudoEntropy, FallbackEntropy}`: `MockEntropy` детерминированно воспроизводит буфер и может эмулировать полный отказ источника, `PseudoEntropy` — лёгкий потоковый ГПСЧ на SHA-256 (без heap), а `FallbackEntropy` автоматически переключается на него при `EntropyUnavailable`. Это покрывается `tests/entropy.rs`.
- В prove/verify используется синхронная детерминированная схема Schnorr: nonce = H("nonce" || domain || challenge || sk), поэтому RNG не нужен, а повторный challenge даёт тот же proof (контролирует verifier). Все временные скаляры и буферы очищаются `zeroize` (см. `identity::keys`, `zk::prover`, `zk::proof`, `storage::flash`), что исключает утечки через RAM.
- Код избегает ветвлений по секретным данным: все проверки `if` завязаны только на публичные условия (challenge длина, доступность ROSC, проверка MAC).

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

- Критические участки (`storage::flash`, `zk::verifier`) используют `log` (с отключёнными `std`-фичами), поэтому можно подключить будь‑то ITM, RTT или host‑bridge. Макросы `info!` сигнализируют о seal/unseal, `warn!` — о подозрительных ситуациях (MAC mismatch, повреждённый слот), `debug!` — о вспомогательных событиях.
- Встраиваемые проекты могут предоставить собственный `log::Log` (например, через `defmt` bridge) или оставить журнал пустым — в этом случае макросы оптимизируются.

## Физические атаки и secure boot

- Состояние во Flash привязано к конкретному RP2040: `storage::flash` смешивает (`DeviceBindingKey::mix_into`) ключи шифрования/MAC с аппаратным `DeviceUid`, извлечённым через ROM (`flash_unique_id`). Даже если атакующий скопирует Flash в другой чип, данные останутся непригодными без UID/PUF исходного устройства.
- Secure boot проверяется перед `unseal`: `platform::secure_boot::{FirmwareRegion,FirmwareGuard}` вычисляют SHA-256 образа XIP-Flash и возвращают `IdentityError::SecureBootFailure`, если hash не совпадает. Встроенный helper `identity::persist::unseal_identity_guarded` обязует вызывающего предоставить контрольную сумму и тем самым блокирует загрузку личности при подмене прошивки.
- Угрозы физического доступа документируются явно: этот README фиксирует сценарии (чтение RAM/Flash, перенос образа на другое устройство, подмена прошивки) и ответные меры (zeroization, device binding, secure boot).

## Эталонная проверка proof

### ZK statement и формат

- ZK-утверждение: «Существует скаляр `sk_user`, такой что `PK = sk_user · G` и `s·G = R + H(domain, challenge, PK, R) · PK`, где `(R, s)` получены от prover». Реализация повторяет детерминированный Schnorr с Fiat–Shamir.
- Domain separation: все хэши включают префиксы `"nonce"`/`"challenge"` плюс выбранную строку домена (по умолчанию `b"zk-gatekeeper-schnorr-v1"`). Это исключает смешение с другими протоколами.
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
- Структуры `contacts::ContactTree` и `ContactWitness` управляют списком контактов: добавление (`add_contact`), удаление/отзыв (`remove_contact`), пересчёт корня и генерация доказательства членства. Дублирующиеся контакты запрещены, переполнение выдаёт `IdentityError::ContactListFull`.
- `contact_set_root()` возвращает текущее значение корня, подходящее для публикации. Оно обновляется при каждом изменении набора.
- Для ZK-проверки членства используйте `ContactTree::membership_proof`, который возвращает `ContactWitness`. Метод `prepare_zk_inputs()` готовит входные данные для гостя: `(root, leaf, siblings[], path_bits[])`, что соответствует statement «мой `PK` находится в твоём дереве контактов».

## Handshake и Double Ratchet

- После успешного ZK-verify устройства выполняют упрощённый Noise IK-подобный обмен на `x25519`: `handshake::initiator_start` формирует первое сообщение (эпемерный ключ + MAC), `handshake::responder_accept` проверяет MAC, генерирует ответ и вычисляет общий секрет. `initiator_finish` завершается после получения ответа. Оба шага используют лишь публичные данные (domain, capability bits) и `EntropySource` для эпемерных ключей.
- Формат `HandshakeMessage`: `version (1)` + `capabilities (u32)` + `ephemeral public key (32 байта)` + `mac (32 байта)`. Все MAC считаются как `HMAC-SHA256(shared_secret, "gatekeeper-noise-mac" || capabilities)`, что фиксирует домен.
- Capability Manager (`handshake::CapabilityFlags/CapabilityManager`) объявляет возможности устройства (VOICE/FILES/TEXT/VIDEO). На выходе обе стороны получают пересечение флагов (например, только VOICE). Эти флаги затем используются при инициализации каналов/функций.
- Итоговый общий секрет поступает в `handshake::RatchetState`, который разворачивает простую Double-Ratchet обвязку: `RatchetState::new(shared_secret)` → цепочки `send/recv`, обновляемые через HKDF при каждом сообщении (`next_send_key`, `next_recv_key`). Состояние (root key + счётчики) можно сохранять во Flash наряду с другими метаданными.

## Secure storage & sync

- `storage::secure::SecureStore` — мини-«SQLCipher»: хранит таблицы `RatchetStateRow` и `ContactMetadata`, применяет WAL (`WalTransaction`) перед каждым коммитом и использует `SecureCipher` (HMAC‑SHA256 поток + MAC) для шифрования снимков. При сбое `recover()` переигрывает незавершённый WAL, обеспечивая атомарность.
- Структура ratchet-state (`RatchetStateRow`) включает `IdentityIdentifier`, ключи цепочек и счётчики. Метаданные контактов (`ContactMetadata`) содержат `IdentityIdentifier`, capability-флаги, `last_seen_epoch` и уровень доверия; это позволяет хранить контактную книжку в том же журнале.
- Для синхронизации с мобильным приложением/хостом вызывайте `SecureStore::snapshot(interface)` — он возвращает `SecureFrame { interface, nonce, payload, mac }`, где `interface ∈ {UART, USB, SPI}`. На принимающей стороне `apply_sync_frame` расшифрует и применит снимок; данные передаются через любой транспорт (UART/USB/SPI) без раскрытия содержимого.
- Payload — детерминированный бинарный формат (`RECORD_VERSION=1`), совместимый с тестами. Благодаря MAC и одноразовым nonce устройство защищено от подмены/повторов, а структура WAL обеспечивает консистентность даже при power-loss.

## Storage Access Gate (offline blobs)

- `storage::gate` реализует анонимный доступ к оффлайн-blob’ам: gate выдаёт `BlobFetchChallenge { blob_id, nonce }`, а устройство формирует `BlobFetchRequest` через `BlobIdentityProver`, используя тот же Schnorr-процедурный каркас, но с доменом `b"zk-gatekeeper-blob-v1"` и challenge = `blob_id || nonce`. Identity не раскрывается на транспортном уровне — gate хранит соответствие `(blob_id, IdentityIdentifier, public_key)` и сверяет proof локально.
- `BlobAccessGate` совместим с P2P-хранилищем (Waku Store и т. п.): запросы содержат минимум метаданных (`blob_id`, `nonce`, `proof`) и могут пересылаться как Waku payload'ы. Gate регистрирует права доступа через `BlobAccessEntry`, делает ревокацию (`revoke`) и возвращает `BlobAccessGrant` при успешной проверке.
- Для интеграции с Waku: узел публикует `blob_id` в качестве темы (`/zk-gatekeeper/blob/<hex>`) и отвечает на fetch-запросы только при получении валидного `BlobFetchRequest`. Challenge можно распространять по side-channel (например, Waku Request/Response или out-of-band), что предотвращает воспроизведение и минимизирует утечки.

## Форматы и API

- **Flash-record v1**: `magic(4="ZKGS") | version(1) | reserved(1) | payload_len(2=64) | counter(4) | reserved(4) | device_id(16) | ciphertext(64: sk_user || pk_user) | mac(32)` — сериализация из `storage::flash`. Несоответствия версий/длины → `IdentityError::StorageVersionMismatch/StorageCorrupted`.

### Wear leveling и ресурс Flash

- Драйвер `storage::flash` использует littlefs-подобный журнал: четыре сектора (по 4 KiB каждый) образуют кольцо слотов. Каждый `seal()` пишет в следующий слот и стирает только его, что даёт равномерный износ и выдерживает ≈100 000 циклов стереть/запись на сектор (≈400 000 циклов на всю область хранения).
- Слотность фиксируется константой `STORAGE_SLOT_COUNT = 4`, но может быть увеличена при необходимости — алгоритм переиспользует слоты по принципу LRU (по счётчику `counter`).
- Хранение совместимо с LittleFS: слоты можно просканировать и из host-приложений, а самый новый выбирается по счётчику. При повреждении последнего слота загрузка откатывается на предыдущий валидный.
- Build-script умеет подстраивать разметку через переменные окружения: `ZK_BOOTLOADER_BYTES` (по умолчанию 0x1000) резервирует начало Flash под бутлоадер, `ZK_STORAGE_SECTORS` задаёт количество wear-leveling слотов. При конфликте скрипт прервёт сборку.
- В README задокументировано ограничение по ресурсам Flash, и при интеграции рекомендуется вести журнал циклов, если устройство работает в тяжёлых условиях.
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
- Для rustdoc доступна встроенная документация с примерами (`cargo doc --no-deps --features "flash-storage contacts handshake secure-storage storage-gate"`). Сгенерированные HTML-файлы лежат в `target/doc/index.html` и могут быть опубликованы на артефакт-сервере/Pages.
- `src/lib.rs` экспортирует минимальный API, дополнительные заметки предполагается хранить в `docs/`.

## no_std-аудит и сборка

- Проект `#![no_std]`; зависимости подключены без `std`. Проверяйте `cargo check --no-default-features --target thumbv6m-none-eabi`.
- Размер и зависимост и: `cargo build --release --target thumbv6m-none-eabi` + `cargo size --target thumbv6m-none-eabi --lib`; `cargo tree --edges no-dev`. Те же команды автоматически выполняются в CI (`.github/workflows/size.yml`) — push/PR падает, если `cargo size` не проходит.
