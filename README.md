# zk-gatekeeper

Experimental `no_std` identity and ZK helper crate for RP2040 deployments.

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
- В prove/verify используется синхронная детерминированная схема Schnorr: nonce = H("nonce" || domain || challenge || sk), поэтому RNG не нужен, а повторный challenge даёт тот же proof (контролирует verifier). Все временные скаляры и буферы очищаются `zeroize` (см. `identity::keys`, `zk::prover`, `zk::proof`, `storage::flash`), что исключает утечки через RAM.
- Код избегает ветвлений по секретным данным: все проверки `if` завязаны только на публичные условия (challenge длина, доступность ROSC, проверка MAC).

## Защита от повторов (replay)

- **Verifier** обязан генерировать уникальные challenge и регистрировать их перед отправкой (`zk::verifier::ChallengeTracker::register`). После получения proof challenge должен быть потреблён (`Verifier::verify` вызывает `consume`), что блокирует его повторное использование.
- **Prover** никогда не кэширует доказательства и не отвечает на пустые либо слишком длинные challenge (см. `DeterministicSchnorrProver::prove` и проверки в `ZkProof::verify`). Повторный challenge детерминированно даёт тот же proof, поэтому именно verifier несёт ответственность за одноразовость значений.
- Если challenge не был зарегистрирован или уже использован, `ChallengeTracker` вернёт `IdentityError::ChallengeNotRegistered` / `ReplayDetected`, и proof отвергнется до криптографической проверки.

## Политика очистки памяти

- Все временные скаляры в криптографических операциях обнуляются через `zeroize` перед выходом (`identity::keys`, `zk::prover`, `zk::proof`).
- В `storage::flash::seal` и `unseal` после каждого шага очищаются временные буферы (ciphertext, ключи, MAC, читаемые заголовки). Это гарантирует, что в RAM не останется корневых ключей после завершения операций.
- Новые API не возвращают ссылки на `sk_user`, а `IdentityState::prove_with` лишь на время жизни вызова создаёт `ZkSecretRef`. Это исключает зависание секретов в структурах верхнего уровня.

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
  1. `Verifier::new(domain)` фиксирует контекст.  
  2. `verifier.tracker_mut().register(challenge)` — одноразовость challenge.  
  3. Получив `(proof, PK, IdentityIdentifier)`, вызывайте `verifier.verify(...)`:  
     - Проверяется `IdentityIdentifier::matches(PK)`.  
     - Challenge помечается использованным; повтор вернёт `ReplayDetected`.  
     - `ZkProof::verify` проверит уравнение Schnorr и версию proof.
- Этот код не зависит от RP2040 и может компилироваться в любых host-программах (см. `tests/zk.rs`).

### Host-тесты и совместимость

- В `tests/zk.rs` есть два интеграционных теста: `prover_verifier_roundtrip` (проверяет совместимость формата prover ↔ verifier) и `replay_detected` (убеждается, что повтор proof по тому же challenge даёт ошибку).
- Для проверки совместимости внешних реализаций используйте `ZK_PROOF_VERSION`, `ZK_PROOF_LEN`, `ZK_COMMITMENT_LEN` и `ZK_RESPONSE_LEN` из `zk::proof`. Любое изменение формата потребует обновления версии и тестов.
