# BlackShield Security Audit Report — `Infisical/cli`

- **Scanned Commit:** `6368c5e7918e6df56108be42f33b728cf173044d`
- **Actionable Findings:** `63` (`1 Critical`, `62 High`, `6 Medium`, `5 Low`)
- **BlackShield Platform & Continuous Zero-Cost PR Protection:** [https://blackshield.chaplau.com](https://blackshield.chaplau.com)

## Detailed Findings & Remediation Guide

### 1. [CRITICAL] `db-conn-mongodb` — MongoDB Connection URI with Plaintext Password

- **Category:** `secret`
- **Location:** `packages/pam/handlers/mongodb/proxy.go:92`
- **Details:** Potential hardcoded credential or secret detected in `packages/pam/handlers/mongodb/proxy.go:92` (rule `db-conn-mongodb`). Raw value redacted (`***REDACTED***`) for safe disclosure.
- **Recommended Fix:** Revoke leaked credential immediately and rotate in secret manager.

### 2. [HIGH] `CKV_DOCKER_1` — CKV_DOCKER_1: Missing Non-Root USER Instruction

- **Category:** `misconfiguration`
- **Location:** `dev/pam/resources/mssql/Dockerfile:6`
- **Details:** Container executes processes as root user by default because no non-root USER instruction was specified.
- **Recommended Fix:** Add 'USER 10001' or a dedicated non-root application user.

### 3. [HIGH] `CKV_DOCKER_1` — CKV_DOCKER_1: Container Runs as Root (Missing Non-Root USER)

- **Category:** `misconfiguration`
- **Location:** `dev/pam/resources/ssh-server/Dockerfile:1`
- **Details:** Container does not specify a non-root USER, allowing processes to execute with root privileges.
- **Recommended Fix:** Add 'USER <non-root-uid>' instruction before container entrypoint.

### 4. [HIGH] `CKV_DOCKER_6` — CKV_DOCKER_6: SSH Port 22 Exposed in Container

- **Category:** `misconfiguration`
- **Location:** `dev/pam/resources/ssh-server/Dockerfile:8`
- **Details:** Containers should not expose SSH port 22; communicate via orchestrator or secure agents instead.
- **Recommended Fix:** Remove 'EXPOSE 22' and avoid running OpenSSH daemon in application containers.

### 5. [HIGH] `go-cmdi-exec-combined` — go-cmdi-exec-combined: Command Execution via Dynamic exec.Command

- **Category:** `sast`
- **Location:** `e2e/util/helpers.go:475`
- **Details:** Go application security vulnerability or insecure coding pattern. at e2e/util/helpers.go:475
- **Recommended Fix:** Invoke the target binary directly with exec.Command(bin, args...) without sh -c shell evaluation.

### 6. [HIGH] `CKV_DOCKER_1` — CKV_DOCKER_1: Container Runs as Root (Missing Non-Root USER)

- **Category:** `misconfiguration`
- **Location:** `goreleaser.dockerfile:1`
- **Details:** Container does not specify a non-root USER, allowing processes to execute with root privileges.
- **Recommended Fix:** Add 'USER <non-root-uid>' instruction before container entrypoint.

### 7. [HIGH] `sec-hardcoded-credentials` — sec-hardcoded-credentials: Hardcoded Password or Secret in Code

- **Category:** `sast`
- **Location:** `packages/agentproxy/rewrite.go:16`
- **Details:** Hardcoding plaintext credentials directly in source files risks repository exposure. at packages/agentproxy/rewrite.go:16
- **Recommended Fix:** Load credentials securely at runtime via environment variables or a secret manager.

### 8. [HIGH] `sec-hardcoded-credentials` — sec-hardcoded-credentials: Hardcoded Password or Secret in Code

- **Category:** `sast`
- **Location:** `packages/agentproxy/rewrite.go:12`
- **Details:** Hardcoding plaintext credentials directly in source files risks repository exposure. at packages/agentproxy/rewrite.go:12
- **Recommended Fix:** Load credentials securely at runtime via environment variables or a secret manager.

### 9. [HIGH] `go-cmdi-exec-combined` — go-cmdi-exec-combined: Command Execution via Dynamic exec.Command

- **Category:** `sast`
- **Location:** `packages/cmd/run.go:228`
- **Details:** Go application security vulnerability or insecure coding pattern. at packages/cmd/run.go:228
- **Recommended Fix:** Invoke the target binary directly with exec.Command(bin, args...) without sh -c shell evaluation.

### 10. [HIGH] `sec-broken-crypto-cipher` — sec-broken-crypto-cipher: Deprecated or Weak Symmetric Cipher Algorithm

- **Category:** `sast`
- **Location:** `packages/gateway-v2/certscan/pkcs12_legacy_pbe.go:97`
- **Details:** Using broken cryptographic algorithms (DES, 3DES, RC4, Blowfish, AES-ECB mode) compromises data confidentiality. at packages/gateway-v2/certscan/pkcs12_legacy_pbe.go:97
- **Recommended Fix:** Use AES-256-GCM or ChaCha20-Poly1305 for symmetric encryption. Avoid ECB mode.

### 11. [HIGH] `native-rust-no-mangle` — native-rust-no-mangle: Unsafe External Export via #[no_mangle]

- **Category:** `sast`
- **Location:** `packages/pam/handlers/rdp/native/src/ffi.rs:274`
- **Details:** Native systems programming security flaw. at packages/pam/handlers/rdp/native/src/ffi.rs:274
- **Recommended Fix:** Prefer safe Rust abstractions and checked conversions (TryFrom/TryInto) over unsafe blocks, raw pointer dereferences, or mem::transmute.

### 12. [HIGH] `native-rust-no-mangle` — native-rust-no-mangle: Unsafe External Export via #[no_mangle]

- **Category:** `sast`
- **Location:** `packages/pam/handlers/rdp/native/src/ffi.rs:333`
- **Details:** Native systems programming security flaw. at packages/pam/handlers/rdp/native/src/ffi.rs:333
- **Recommended Fix:** Prefer safe Rust abstractions and checked conversions (TryFrom/TryInto) over unsafe blocks, raw pointer dereferences, or mem::transmute.

### 13. [HIGH] `native-rust-no-mangle` — native-rust-no-mangle: Unsafe External Export via #[no_mangle]

- **Category:** `sast`
- **Location:** `packages/pam/handlers/rdp/native/src/ffi.rs:388`
- **Details:** Native systems programming security flaw. at packages/pam/handlers/rdp/native/src/ffi.rs:388
- **Recommended Fix:** Prefer safe Rust abstractions and checked conversions (TryFrom/TryInto) over unsafe blocks, raw pointer dereferences, or mem::transmute.

### 14. [HIGH] `native-rust-no-mangle` — native-rust-no-mangle: Unsafe External Export via #[no_mangle]

- **Category:** `sast`
- **Location:** `packages/pam/handlers/rdp/native/src/ffi.rs:434`
- **Details:** Native systems programming security flaw. at packages/pam/handlers/rdp/native/src/ffi.rs:434
- **Recommended Fix:** Prefer safe Rust abstractions and checked conversions (TryFrom/TryInto) over unsafe blocks, raw pointer dereferences, or mem::transmute.

### 15. [HIGH] `native-rust-no-mangle` — native-rust-no-mangle: Unsafe External Export via #[no_mangle]

- **Category:** `sast`
- **Location:** `packages/pam/handlers/rdp/native/src/ffi.rs:465`
- **Details:** Native systems programming security flaw. at packages/pam/handlers/rdp/native/src/ffi.rs:465
- **Recommended Fix:** Prefer safe Rust abstractions and checked conversions (TryFrom/TryInto) over unsafe blocks, raw pointer dereferences, or mem::transmute.

### 16. [HIGH] `native-rust-no-mangle` — native-rust-no-mangle: Unsafe External Export via #[no_mangle]

- **Category:** `sast`
- **Location:** `packages/pam/handlers/rdp/native/src/ffi.rs:477`
- **Details:** Native systems programming security flaw. at packages/pam/handlers/rdp/native/src/ffi.rs:477
- **Recommended Fix:** Prefer safe Rust abstractions and checked conversions (TryFrom/TryInto) over unsafe blocks, raw pointer dereferences, or mem::transmute.

### 17. [HIGH] `native-rust-no-mangle` — native-rust-no-mangle: Unsafe External Export via #[no_mangle]

- **Category:** `sast`
- **Location:** `packages/pam/handlers/rdp/native/src/ffi.rs:493`
- **Details:** Native systems programming security flaw. at packages/pam/handlers/rdp/native/src/ffi.rs:493
- **Recommended Fix:** Prefer safe Rust abstractions and checked conversions (TryFrom/TryInto) over unsafe blocks, raw pointer dereferences, or mem::transmute.

### 18. [HIGH] `native-rust-raw-pointer-deref` — native-rust-raw-pointer-deref: Raw Pointer Dereference in Rust

- **Category:** `sast`
- **Location:** `packages/pam/handlers/rdp/native/src/ffi.rs:60`
- **Details:** Native systems programming security flaw. at packages/pam/handlers/rdp/native/src/ffi.rs:60
- **Recommended Fix:** Prefer safe Rust abstractions and checked conversions (TryFrom/TryInto) over unsafe blocks, raw pointer dereferences, or mem::transmute.

### 19. [HIGH] `native-rust-raw-pointer-deref` — native-rust-raw-pointer-deref: Raw Pointer Dereference in Rust

- **Category:** `sast`
- **Location:** `packages/pam/handlers/rdp/native/src/ffi.rs:131`
- **Details:** Native systems programming security flaw. at packages/pam/handlers/rdp/native/src/ffi.rs:131
- **Recommended Fix:** Prefer safe Rust abstractions and checked conversions (TryFrom/TryInto) over unsafe blocks, raw pointer dereferences, or mem::transmute.

### 20. [HIGH] `native-rust-raw-pointer-deref` — native-rust-raw-pointer-deref: Raw Pointer Dereference in Rust

- **Category:** `sast`
- **Location:** `packages/pam/handlers/rdp/native/src/ffi.rs:185`
- **Details:** Native systems programming security flaw. at packages/pam/handlers/rdp/native/src/ffi.rs:185
- **Recommended Fix:** Prefer safe Rust abstractions and checked conversions (TryFrom/TryInto) over unsafe blocks, raw pointer dereferences, or mem::transmute.

### 21. [HIGH] `native-rust-raw-pointer-deref` — native-rust-raw-pointer-deref: Raw Pointer Dereference in Rust

- **Category:** `sast`
- **Location:** `packages/pam/handlers/rdp/native/src/ffi.rs:277`
- **Details:** Native systems programming security flaw. at packages/pam/handlers/rdp/native/src/ffi.rs:277
- **Recommended Fix:** Prefer safe Rust abstractions and checked conversions (TryFrom/TryInto) over unsafe blocks, raw pointer dereferences, or mem::transmute.

### 22. [HIGH] `native-rust-raw-pointer-deref` — native-rust-raw-pointer-deref: Raw Pointer Dereference in Rust

- **Category:** `sast`
- **Location:** `packages/pam/handlers/rdp/native/src/ffi.rs:279`
- **Details:** Native systems programming security flaw. at packages/pam/handlers/rdp/native/src/ffi.rs:279
- **Recommended Fix:** Prefer safe Rust abstractions and checked conversions (TryFrom/TryInto) over unsafe blocks, raw pointer dereferences, or mem::transmute.

### 23. [HIGH] `native-rust-raw-pointer-deref` — native-rust-raw-pointer-deref: Raw Pointer Dereference in Rust

- **Category:** `sast`
- **Location:** `packages/pam/handlers/rdp/native/src/ffi.rs:280`
- **Details:** Native systems programming security flaw. at packages/pam/handlers/rdp/native/src/ffi.rs:280
- **Recommended Fix:** Prefer safe Rust abstractions and checked conversions (TryFrom/TryInto) over unsafe blocks, raw pointer dereferences, or mem::transmute.

### 24. [HIGH] `native-rust-raw-pointer-deref` — native-rust-raw-pointer-deref: Raw Pointer Dereference in Rust

- **Category:** `sast`
- **Location:** `packages/pam/handlers/rdp/native/src/ffi.rs:281`
- **Details:** Native systems programming security flaw. at packages/pam/handlers/rdp/native/src/ffi.rs:281
- **Recommended Fix:** Prefer safe Rust abstractions and checked conversions (TryFrom/TryInto) over unsafe blocks, raw pointer dereferences, or mem::transmute.

### 25. [HIGH] `native-rust-raw-pointer-deref` — native-rust-raw-pointer-deref: Raw Pointer Dereference in Rust

- **Category:** `sast`
- **Location:** `packages/pam/handlers/rdp/native/src/ffi.rs:282`
- **Details:** Native systems programming security flaw. at packages/pam/handlers/rdp/native/src/ffi.rs:282
- **Recommended Fix:** Prefer safe Rust abstractions and checked conversions (TryFrom/TryInto) over unsafe blocks, raw pointer dereferences, or mem::transmute.

### 26. [HIGH] `native-rust-raw-pointer-deref` — native-rust-raw-pointer-deref: Raw Pointer Dereference in Rust

- **Category:** `sast`
- **Location:** `packages/pam/handlers/rdp/native/src/ffi.rs:283`
- **Details:** Native systems programming security flaw. at packages/pam/handlers/rdp/native/src/ffi.rs:283
- **Recommended Fix:** Prefer safe Rust abstractions and checked conversions (TryFrom/TryInto) over unsafe blocks, raw pointer dereferences, or mem::transmute.

### 27. [HIGH] `native-rust-raw-pointer-deref` — native-rust-raw-pointer-deref: Raw Pointer Dereference in Rust

- **Category:** `sast`
- **Location:** `packages/pam/handlers/rdp/native/src/ffi.rs:336`
- **Details:** Native systems programming security flaw. at packages/pam/handlers/rdp/native/src/ffi.rs:336
- **Recommended Fix:** Prefer safe Rust abstractions and checked conversions (TryFrom/TryInto) over unsafe blocks, raw pointer dereferences, or mem::transmute.

### 28. [HIGH] `native-rust-raw-pointer-deref` — native-rust-raw-pointer-deref: Raw Pointer Dereference in Rust

- **Category:** `sast`
- **Location:** `packages/pam/handlers/rdp/native/src/ffi.rs:338`
- **Details:** Native systems programming security flaw. at packages/pam/handlers/rdp/native/src/ffi.rs:338
- **Recommended Fix:** Prefer safe Rust abstractions and checked conversions (TryFrom/TryInto) over unsafe blocks, raw pointer dereferences, or mem::transmute.

### 29. [HIGH] `native-rust-raw-pointer-deref` — native-rust-raw-pointer-deref: Raw Pointer Dereference in Rust

- **Category:** `sast`
- **Location:** `packages/pam/handlers/rdp/native/src/ffi.rs:339`
- **Details:** Native systems programming security flaw. at packages/pam/handlers/rdp/native/src/ffi.rs:339
- **Recommended Fix:** Prefer safe Rust abstractions and checked conversions (TryFrom/TryInto) over unsafe blocks, raw pointer dereferences, or mem::transmute.

### 30. [HIGH] `native-rust-raw-pointer-deref` — native-rust-raw-pointer-deref: Raw Pointer Dereference in Rust

- **Category:** `sast`
- **Location:** `packages/pam/handlers/rdp/native/src/ffi.rs:340`
- **Details:** Native systems programming security flaw. at packages/pam/handlers/rdp/native/src/ffi.rs:340
- **Recommended Fix:** Prefer safe Rust abstractions and checked conversions (TryFrom/TryInto) over unsafe blocks, raw pointer dereferences, or mem::transmute.

### 31. [HIGH] `native-rust-raw-pointer-deref` — native-rust-raw-pointer-deref: Raw Pointer Dereference in Rust

- **Category:** `sast`
- **Location:** `packages/pam/handlers/rdp/native/src/ffi.rs:341`
- **Details:** Native systems programming security flaw. at packages/pam/handlers/rdp/native/src/ffi.rs:341
- **Recommended Fix:** Prefer safe Rust abstractions and checked conversions (TryFrom/TryInto) over unsafe blocks, raw pointer dereferences, or mem::transmute.

### 32. [HIGH] `native-rust-raw-pointer-deref` — native-rust-raw-pointer-deref: Raw Pointer Dereference in Rust

- **Category:** `sast`
- **Location:** `packages/pam/handlers/rdp/native/src/ffi.rs:342`
- **Details:** Native systems programming security flaw. at packages/pam/handlers/rdp/native/src/ffi.rs:342
- **Recommended Fix:** Prefer safe Rust abstractions and checked conversions (TryFrom/TryInto) over unsafe blocks, raw pointer dereferences, or mem::transmute.

### 33. [HIGH] `native-rust-raw-pointer-deref` — native-rust-raw-pointer-deref: Raw Pointer Dereference in Rust

- **Category:** `sast`
- **Location:** `packages/pam/handlers/rdp/native/src/ffi.rs:437`
- **Details:** Native systems programming security flaw. at packages/pam/handlers/rdp/native/src/ffi.rs:437
- **Recommended Fix:** Prefer safe Rust abstractions and checked conversions (TryFrom/TryInto) over unsafe blocks, raw pointer dereferences, or mem::transmute.

### 34. [HIGH] `native-rust-raw-pointer-deref` — native-rust-raw-pointer-deref: Raw Pointer Dereference in Rust

- **Category:** `sast`
- **Location:** `packages/pam/handlers/rdp/native/src/ffi.rs:496`
- **Details:** Native systems programming security flaw. at packages/pam/handlers/rdp/native/src/ffi.rs:496
- **Recommended Fix:** Prefer safe Rust abstractions and checked conversions (TryFrom/TryInto) over unsafe blocks, raw pointer dereferences, or mem::transmute.

### 35. [HIGH] `native-rust-raw-pointer-deref` — native-rust-raw-pointer-deref: Raw Pointer Dereference in Rust

- **Category:** `sast`
- **Location:** `packages/pam/handlers/rdp/native/src/ffi.rs:275`
- **Details:** Native systems programming security flaw. at packages/pam/handlers/rdp/native/src/ffi.rs:275
- **Recommended Fix:** Prefer safe Rust abstractions and checked conversions (TryFrom/TryInto) over unsafe blocks, raw pointer dereferences, or mem::transmute.

### 36. [HIGH] `native-rust-raw-pointer-deref` — native-rust-raw-pointer-deref: Raw Pointer Dereference in Rust

- **Category:** `sast`
- **Location:** `packages/pam/handlers/rdp/native/src/ffi.rs:334`
- **Details:** Native systems programming security flaw. at packages/pam/handlers/rdp/native/src/ffi.rs:334
- **Recommended Fix:** Prefer safe Rust abstractions and checked conversions (TryFrom/TryInto) over unsafe blocks, raw pointer dereferences, or mem::transmute.

### 37. [HIGH] `native-rust-raw-pointer-deref` — native-rust-raw-pointer-deref: Raw Pointer Dereference in Rust

- **Category:** `sast`
- **Location:** `packages/pam/handlers/rdp/native/src/ffi.rs:435`
- **Details:** Native systems programming security flaw. at packages/pam/handlers/rdp/native/src/ffi.rs:435
- **Recommended Fix:** Prefer safe Rust abstractions and checked conversions (TryFrom/TryInto) over unsafe blocks, raw pointer dereferences, or mem::transmute.

### 38. [HIGH] `native-rust-raw-pointer-deref` — native-rust-raw-pointer-deref: Raw Pointer Dereference in Rust

- **Category:** `sast`
- **Location:** `packages/pam/handlers/rdp/native/src/ffi.rs:494`
- **Details:** Native systems programming security flaw. at packages/pam/handlers/rdp/native/src/ffi.rs:494
- **Recommended Fix:** Prefer safe Rust abstractions and checked conversions (TryFrom/TryInto) over unsafe blocks, raw pointer dereferences, or mem::transmute.

### 39. [HIGH] `native-rust-unsafe-block` — native-rust-unsafe-block: Unsafe Block Usage in Rust

- **Category:** `sast`
- **Location:** `packages/pam/handlers/rdp/native/src/ffi.rs:130`
- **Details:** Native systems programming security flaw. at packages/pam/handlers/rdp/native/src/ffi.rs:130
- **Recommended Fix:** Prefer safe Rust abstractions and checked conversions (TryFrom/TryInto) over unsafe blocks, raw pointer dereferences, or mem::transmute.

### 40. [HIGH] `native-rust-unsafe-block` — native-rust-unsafe-block: Unsafe Block Usage in Rust

- **Category:** `sast`
- **Location:** `packages/pam/handlers/rdp/native/src/ffi.rs:189`
- **Details:** Native systems programming security flaw. at packages/pam/handlers/rdp/native/src/ffi.rs:189
- **Recommended Fix:** Prefer safe Rust abstractions and checked conversions (TryFrom/TryInto) over unsafe blocks, raw pointer dereferences, or mem::transmute.

### 41. [HIGH] `native-rust-unsafe-block` — native-rust-unsafe-block: Unsafe Block Usage in Rust

- **Category:** `sast`
- **Location:** `packages/pam/handlers/rdp/native/src/ffi.rs:288`
- **Details:** Native systems programming security flaw. at packages/pam/handlers/rdp/native/src/ffi.rs:288
- **Recommended Fix:** Prefer safe Rust abstractions and checked conversions (TryFrom/TryInto) over unsafe blocks, raw pointer dereferences, or mem::transmute.

### 42. [HIGH] `native-rust-unsafe-block` — native-rust-unsafe-block: Unsafe Block Usage in Rust

- **Category:** `sast`
- **Location:** `packages/pam/handlers/rdp/native/src/ffi.rs:292`
- **Details:** Native systems programming security flaw. at packages/pam/handlers/rdp/native/src/ffi.rs:292
- **Recommended Fix:** Prefer safe Rust abstractions and checked conversions (TryFrom/TryInto) over unsafe blocks, raw pointer dereferences, or mem::transmute.

### 43. [HIGH] `native-rust-unsafe-block` — native-rust-unsafe-block: Unsafe Block Usage in Rust

- **Category:** `sast`
- **Location:** `packages/pam/handlers/rdp/native/src/ffi.rs:296`
- **Details:** Native systems programming security flaw. at packages/pam/handlers/rdp/native/src/ffi.rs:296
- **Recommended Fix:** Prefer safe Rust abstractions and checked conversions (TryFrom/TryInto) over unsafe blocks, raw pointer dereferences, or mem::transmute.

### 44. [HIGH] `native-rust-unsafe-block` — native-rust-unsafe-block: Unsafe Block Usage in Rust

- **Category:** `sast`
- **Location:** `packages/pam/handlers/rdp/native/src/ffi.rs:300`
- **Details:** Native systems programming security flaw. at packages/pam/handlers/rdp/native/src/ffi.rs:300
- **Recommended Fix:** Prefer safe Rust abstractions and checked conversions (TryFrom/TryInto) over unsafe blocks, raw pointer dereferences, or mem::transmute.

### 45. [HIGH] `native-rust-unsafe-block` — native-rust-unsafe-block: Unsafe Block Usage in Rust

- **Category:** `sast`
- **Location:** `packages/pam/handlers/rdp/native/src/ffi.rs:301`
- **Details:** Native systems programming security flaw. at packages/pam/handlers/rdp/native/src/ffi.rs:301
- **Recommended Fix:** Prefer safe Rust abstractions and checked conversions (TryFrom/TryInto) over unsafe blocks, raw pointer dereferences, or mem::transmute.

### 46. [HIGH] `native-rust-unsafe-block` — native-rust-unsafe-block: Unsafe Block Usage in Rust

- **Category:** `sast`
- **Location:** `packages/pam/handlers/rdp/native/src/ffi.rs:307`
- **Details:** Native systems programming security flaw. at packages/pam/handlers/rdp/native/src/ffi.rs:307
- **Recommended Fix:** Prefer safe Rust abstractions and checked conversions (TryFrom/TryInto) over unsafe blocks, raw pointer dereferences, or mem::transmute.

### 47. [HIGH] `native-rust-unsafe-block` — native-rust-unsafe-block: Unsafe Block Usage in Rust

- **Category:** `sast`
- **Location:** `packages/pam/handlers/rdp/native/src/ffi.rs:319`
- **Details:** Native systems programming security flaw. at packages/pam/handlers/rdp/native/src/ffi.rs:319
- **Recommended Fix:** Prefer safe Rust abstractions and checked conversions (TryFrom/TryInto) over unsafe blocks, raw pointer dereferences, or mem::transmute.

### 48. [HIGH] `native-rust-unsafe-block` — native-rust-unsafe-block: Unsafe Block Usage in Rust

- **Category:** `sast`
- **Location:** `packages/pam/handlers/rdp/native/src/ffi.rs:347`
- **Details:** Native systems programming security flaw. at packages/pam/handlers/rdp/native/src/ffi.rs:347
- **Recommended Fix:** Prefer safe Rust abstractions and checked conversions (TryFrom/TryInto) over unsafe blocks, raw pointer dereferences, or mem::transmute.

### 49. [HIGH] `native-rust-unsafe-block` — native-rust-unsafe-block: Unsafe Block Usage in Rust

- **Category:** `sast`
- **Location:** `packages/pam/handlers/rdp/native/src/ffi.rs:351`
- **Details:** Native systems programming security flaw. at packages/pam/handlers/rdp/native/src/ffi.rs:351
- **Recommended Fix:** Prefer safe Rust abstractions and checked conversions (TryFrom/TryInto) over unsafe blocks, raw pointer dereferences, or mem::transmute.

### 50. [HIGH] `native-rust-unsafe-block` — native-rust-unsafe-block: Unsafe Block Usage in Rust

- **Category:** `sast`
- **Location:** `packages/pam/handlers/rdp/native/src/ffi.rs:355`
- **Details:** Native systems programming security flaw. at packages/pam/handlers/rdp/native/src/ffi.rs:355
- **Recommended Fix:** Prefer safe Rust abstractions and checked conversions (TryFrom/TryInto) over unsafe blocks, raw pointer dereferences, or mem::transmute.

### 51. [HIGH] `native-rust-unsafe-block` — native-rust-unsafe-block: Unsafe Block Usage in Rust

- **Category:** `sast`
- **Location:** `packages/pam/handlers/rdp/native/src/ffi.rs:359`
- **Details:** Native systems programming security flaw. at packages/pam/handlers/rdp/native/src/ffi.rs:359
- **Recommended Fix:** Prefer safe Rust abstractions and checked conversions (TryFrom/TryInto) over unsafe blocks, raw pointer dereferences, or mem::transmute.

### 52. [HIGH] `native-rust-unsafe-block` — native-rust-unsafe-block: Unsafe Block Usage in Rust

- **Category:** `sast`
- **Location:** `packages/pam/handlers/rdp/native/src/ffi.rs:360`
- **Details:** Native systems programming security flaw. at packages/pam/handlers/rdp/native/src/ffi.rs:360
- **Recommended Fix:** Prefer safe Rust abstractions and checked conversions (TryFrom/TryInto) over unsafe blocks, raw pointer dereferences, or mem::transmute.

### 53. [HIGH] `native-rust-unsafe-block` — native-rust-unsafe-block: Unsafe Block Usage in Rust

- **Category:** `sast`
- **Location:** `packages/pam/handlers/rdp/native/src/ffi.rs:366`
- **Details:** Native systems programming security flaw. at packages/pam/handlers/rdp/native/src/ffi.rs:366
- **Recommended Fix:** Prefer safe Rust abstractions and checked conversions (TryFrom/TryInto) over unsafe blocks, raw pointer dereferences, or mem::transmute.

### 54. [HIGH] `native-rust-unsafe-block` — native-rust-unsafe-block: Unsafe Block Usage in Rust

- **Category:** `sast`
- **Location:** `packages/pam/handlers/rdp/native/src/ffi.rs:378`
- **Details:** Native systems programming security flaw. at packages/pam/handlers/rdp/native/src/ffi.rs:378
- **Recommended Fix:** Prefer safe Rust abstractions and checked conversions (TryFrom/TryInto) over unsafe blocks, raw pointer dereferences, or mem::transmute.

### 55. [HIGH] `native-rust-unsafe-block` — native-rust-unsafe-block: Unsafe Block Usage in Rust

- **Category:** `sast`
- **Location:** `packages/pam/handlers/rdp/native/src/ffi.rs:449`
- **Details:** Native systems programming security flaw. at packages/pam/handlers/rdp/native/src/ffi.rs:449
- **Recommended Fix:** Prefer safe Rust abstractions and checked conversions (TryFrom/TryInto) over unsafe blocks, raw pointer dereferences, or mem::transmute.

### 56. [HIGH] `native-rust-unsafe-block` — native-rust-unsafe-block: Unsafe Block Usage in Rust

- **Category:** `sast`
- **Location:** `packages/pam/handlers/rdp/native/src/ffi.rs:458`
- **Details:** Native systems programming security flaw. at packages/pam/handlers/rdp/native/src/ffi.rs:458
- **Recommended Fix:** Prefer safe Rust abstractions and checked conversions (TryFrom/TryInto) over unsafe blocks, raw pointer dereferences, or mem::transmute.

### 57. [HIGH] `native-rust-unsafe-block` — native-rust-unsafe-block: Unsafe Block Usage in Rust

- **Category:** `sast`
- **Location:** `packages/pam/handlers/rdp/native/src/ffi.rs:539`
- **Details:** Native systems programming security flaw. at packages/pam/handlers/rdp/native/src/ffi.rs:539
- **Recommended Fix:** Prefer safe Rust abstractions and checked conversions (TryFrom/TryInto) over unsafe blocks, raw pointer dereferences, or mem::transmute.

### 58. [HIGH] `sec-hardcoded-credentials` — sec-hardcoded-credentials: Hardcoded Password or Secret in Code

- **Category:** `sast`
- **Location:** `packages/pam/handlers/snowflake/proxy.go:43`
- **Details:** Hardcoding plaintext credentials directly in source files risks repository exposure. at packages/pam/handlers/snowflake/proxy.go:43
- **Recommended Fix:** Load credentials securely at runtime via environment variables or a secret manager.

### 59. [HIGH] `sec-hardcoded-credentials` — sec-hardcoded-credentials: Hardcoded Password or Secret in Code

- **Category:** `sast`
- **Location:** `packages/pam/handlers/snowflake/proxy.go:40`
- **Details:** Hardcoding plaintext credentials directly in source files risks repository exposure. at packages/pam/handlers/snowflake/proxy.go:40
- **Recommended Fix:** Load credentials securely at runtime via environment variables or a secret manager.

### 60. [HIGH] `go-cmdi-exec-combined` — go-cmdi-exec-combined: Command Execution via Dynamic exec.Command

- **Category:** `sast`
- **Location:** `packages/pam/local/azure-proxy.go:391`
- **Details:** Go application security vulnerability or insecure coding pattern. at packages/pam/local/azure-proxy.go:391
- **Recommended Fix:** Invoke the target binary directly with exec.Command(bin, args...) without sh -c shell evaluation.

### 61. [HIGH] `go-cmdi-exec-combined` — go-cmdi-exec-combined: Command Execution via Dynamic exec.Command

- **Category:** `sast`
- **Location:** `packages/sandbox/bwrap.go:71`
- **Details:** Go application security vulnerability or insecure coding pattern. at packages/sandbox/bwrap.go:71
- **Recommended Fix:** Invoke the target binary directly with exec.Command(bin, args...) without sh -c shell evaluation.

### 62. [HIGH] `go-cmdi-exec-combined` — go-cmdi-exec-combined: Command Execution via Dynamic exec.Command

- **Category:** `sast`
- **Location:** `packages/util/auth.go:76`
- **Details:** Go application security vulnerability or insecure coding pattern. at packages/util/auth.go:76
- **Recommended Fix:** Invoke the target binary directly with exec.Command(bin, args...) without sh -c shell evaluation.

### 63. [HIGH] `sec-hardcoded-credentials` — sec-hardcoded-credentials: Hardcoded Password or Secret in Code

- **Category:** `sast`
- **Location:** `packages/util/constants.go:66`
- **Details:** Hardcoding plaintext credentials directly in source files risks repository exposure. at packages/util/constants.go:66
- **Recommended Fix:** Load credentials securely at runtime via environment variables or a secret manager.

