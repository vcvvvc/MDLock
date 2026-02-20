# MDLOCK Implementation Plan (Reset)

## Context
- Goal: Build MDLOCK CLI (`mdlock-enc`, `mdlock-dec`) step-by-step for beginner-friendly delivery.
- Current repo state:
  - Dependency baseline is ready in `go.mod` (`github.com/vcvvvc/go-wallet-sdk/crypto`).
  - CLI skeleton has been rebuilt under `cmd/`.
  - No crypto workflow is wired yet.

## Progress
- [x] M0: Recreate CLI entry skeleton.
  - `cmd/mdlock-enc/main.go`
  - `cmd/mdlock-dec/main.go`
- [x] M1: Freeze minimal argument + exit-code behavior.
  - Required: `-mnemonic-env`
  - Error path: `exit 1`
  - Minimal success path: `exit 0`
- [x] Tests for M0/M1 pass:
  - `go test ./...`

## Next Steps
- [x] M2: Implement path rule module (`m/44'/60'/0'/0/<i>` strict validation).
- [x] M3: Implement mnemonic canonicalization (NFKD/whitespace/lowercase policy per docs).
- [ ] M4: Implement key derivation with forked BIP modules.
- [ ] M5: Implement encryption core (HKDF + AES-256-GCM + AAD template).
- [ ] M6: Implement strict markdown envelope parser/builder.
- [ ] M7: Wire end-to-end CLI workflows and error mapping.
- [ ] M8: Complete round-trip/tamper/error-code tests.

## Execution Rules
- Keep each change small and verifiable.
- Run diagnostics after each edit.
- Keep `_PLAN.md` as the single progress anchor.

## Notes
- Dependency source: `github.com/vcvvvc/go-wallet-sdk/crypto` (v0.1.0).
