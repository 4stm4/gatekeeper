# zk-gatekeeper

Experimental `no_std` identity and ZK helper crate for RP2040 deployments.

## Модель личности

- **Публичный ключ** вычисляется детерминированно: `PK = sk_user · G`. Ключ не хранится в Flash, но доступен через `IdentityState::public_key()`.
- **Идентификатор личности** — это `IdentityIdentifier = SHA256("zk-gatekeeper-identity" || PK)`. Он стабильный и публичный, поэтому именно его рекомендуемые хранить verifier'у для линковки устройств. Два proof считаются принадлежащими одной личности тогда, когда совпадает `IdentityIdentifier`. Новое устройство с другим `sk_user` → другой `PK` → другой идентификатор.
- `IdentityState::identifier()` возвращает готовое значение, а на стороне проверки `IdentityIdentifier::matches(public_key)` гарантирует, что предъявленный `PK` действительно принадлежит ожидаемой личности.

## Защита от повторов (replay)

- **Verifier** обязан генерировать уникальные challenge и регистрировать их перед отправкой (`zk::verifier::ChallengeTracker::register`). После получения proof challenge должен быть потреблён (`Verifier::verify` вызывает `consume`), что блокирует его повторное использование.
- **Prover** никогда не кэширует доказательства и не отвечает на пустые либо слишком длинные challenge (см. `DeterministicSchnorrProver::prove` и проверки в `ZkProof::verify`). Повторный challenge детерминированно даёт тот же proof, поэтому именно verifier несёт ответственность за одноразовость значений.
- Если challenge не был зарегистрирован или уже использован, `ChallengeTracker` вернёт `IdentityError::ChallengeNotRegistered` / `ReplayDetected`, и proof отвергнется до криптографической проверки.

## Политика очистки памяти

- Все временные скаляры в криптографических операциях обнуляются через `zeroize` перед выходом (`identity::keys`, `zk::prover`, `zk::proof`).
- В `storage::flash::seal` и `unseal` после каждого шага очищаются временные буферы (ciphertext, ключи, MAC, читаемые заголовки). Это гарантирует, что в RAM не останется корневых ключей после завершения операций.
- Новые API не возвращают ссылки на `sk_user`, а `IdentityState::prove_with` лишь на время жизни вызова создаёт `ZkSecretRef`. Это исключает зависание секретов в структурах верхнего уровня.

## Эталонная проверка proof

Минимальный стек проверки находится в `zk::verifier`:

1. Инициализируйте `Verifier` с выбранным доменом (`Verifier::new(b"zk-gatekeeper-schnorr-v1")`).
2. Перед отправкой challenge устройству вызовите `verifier.tracker_mut().register(challenge)` — это зафиксирует одноразовость.
3. Получив `proof` и `public_key`, вызовите `verifier.verify(&identity_identifier, public_key, challenge, &proof)`.
   - Функция убедится, что `public_key` соответствует ожидаемому `IdentityIdentifier`.
   - Challenge будет помечен как использованный; повторные proof с тем же challenge будут отвергнуты (`ReplayDetected`).
   - `ZkProof::verify` проверит равенство `s·G = R + e·PK`, где `e` — детерминированный транскрипт от домена, challenge, `PK` и `R`.

Такой verifier можно портировать на любой хост (ПК, смартфон, другое MCU), и он служит эталоном для тестов совместимости с прошивкой RP2040.
