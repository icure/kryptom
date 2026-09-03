# Pairing codes: implementation report

Companion to `PAIRING_PLAN.md`. Written 2026-09-03 when the plan was implemented.

## Where things landed

| Concern | Location |
|---|---|
| secp160r1 field and curve arithmetic (`Fp160`, `Secp160r1`, verbatim from the verified tarball) | kryptom `lib/src/commonMain/kotlin/com/icure/kryptom/crypto/ec/` |
| Public curve API: `Secp160r1Service`, `PureKotlinSecp160r1Service`, `CryptoService.secp160r1` | kryptom, same package; default member on `CryptoService` |
| JS/TypeScript surface: `XSecp160r1Service`, optional in `PartialXCryptoService`, pure-Kotlin fallback | kryptom `lib/src/jsMain/.../crypto/external/` |
| `HkdfSha256` (RFC 5869) with its own HMAC-SHA256 over `DigestService.sha256` | kryptom `com.icure.kryptom.crypto` |
| `constantTimeEquals` | kryptom `com.icure.kryptom.utils` |
| Python reference, `vectors.json`, `gen_vectors_kt.py` | kryptom `tools/secp160r1-ref/` |
| Curve, service, HKDF/HMAC and constant-time tests | kryptom `lib/src/commonTest/...` |
| Crockford codec, `PairingCode` (§5), `PairingInitiator`/`PairingResponder` (§6), `lengthPrefixed` | cardinal-sdk `com.icure.cardinal.sdk.crypto.pairing` |
| Format, protocol and randomness tests (§8) | cardinal-sdk `cardinal-sdk/src/commonTest/.../crypto/pairing/` |

kryptom is at 1.7.0; cardinal-sdk depends on 1.7.0 (resolved from `mavenLocal()` until it is released).

## Verification

- kryptom: JVM 123 tests, JS (Node) 127, macOS arm64 123, Android host 123, iOS simulator 123, all green;
  every target kryptom declares compiled for `publishToMavenLocal` (Linux via Homebrew OpenSSL, mingwX64 cross-compiled).
  The 26 curve tests are the tarball's, unchanged except for the kotest `StringSpec` harness.
- HKDF matches RFC 5869 test cases 1–3, the internal HMAC matches RFC 4231 cases 1–4, 6, 7, and both match the
  Python reference (`Vectors.kdf`).
- cardinal-sdk: 31 pairing tests, green on the JVM (three consecutive runs) and on Node. The code format matches all 5 reference
  codes string-for-string; all 5,580 single-symbol substitutions and 170 adjacent transpositions of the reference
  codes are rejected (verified independently in Python first, then asserted exactly in the Kotlin test).

Running a single kotest 6.1 spec through Gradle: `--tests 'pkg.Spec.*'` with the trailing `.*`, one pattern per
invocation; a package pattern (`--tests 'pkg.*'`) runs several specs. A bare class name, or two patterns, silently
runs zero or only one spec. In cardinal-sdk, `TEST_MODE=ci` must be set or the task tries to start the docker
environment.

## Mutation pass (§9)

Each mutant was applied, the relevant specs run with `--no-build-cache --rerun`, and the source restored.

### Curve layer (kryptom, `CurveTest` + `Secp160r1ServiceTest`)

| Mutant | Result | Killed by |
|---|---|---|
| point validation removed from `decompress` (non-residue accepted) | killed | in kryptom: `decompressionMatchesVectors`, `decompressedPointsSatisfyTheCurveEquation`, `ecdhRejectsAnInvalidPeerKey`, service validation and ecdh-null tests. Republished to mavenLocal and run against cardinal-sdk: killed by exactly the two deliberate off-curve tests (`a code whose key is off the curve but passes its checksum yields InvalidKey`, `an envelope whose responder key is off the curve yields InvalidKey`) |
| `lessThanPMask` check dropped (x ≥ p accepted) | killed | same tests, through the `x ≥ p` decompress vectors |
| `mulSmall(beta, 8)` → `mulSmall(beta, 4)` in `jDouble` | killed | `scalarMultiplicationMatchesVectors`, `publicKeyDerivationMatchesVectors`, ecdh vectors, `scalarMultiplicationByOrderIsInfinity` |
| `addComplete`: p-at-infinity selection dropped | killed | scalar vectors, `scalarOneYieldsTheGenerator`, ecdh symmetry |
| random scalar narrowed (16 of 20 random bytes used) | killed | `random scalars use all 160 bits` (added: output uniformity cannot see this, only the scalars can) |

The plan's "addComplete precedence reordered" mutant is equivalent code here: `jAdd` already yields infinity for
p = −q (h = 0 forces z₃ = 0), and the `same` selection is only reachable when the accumulator equals the base point,
which the double-and-add-always ladder never produces. Dropping the infinity selections is the effective mutant and
is the one run.

### Scheme (cardinal-sdk, `PairingCodeTest` + `PairingProtocolTest`)

| Mutant | Result | Killed by |
|---|---|---|
| checksum verification removed | killed | single-symbol substitution, adjacent transposition, responder code-problem tests |
| length-prefixing → plain concatenation | killed | LP ambiguity test, code vectors, KDF/MAC known-answer test |
| responder key dropped from the KDF transcript | killed | KDF/MAC known-answer test. **Not** by the cross-session test the plan names: the shared secret already differs between sessions, so that test cannot see the transcript. |
| version dropped from the KDF transcript | killed | KDF/MAC known-answer test (same reasoning) |
| MAC compared with `contentEquals` | **survived** | not unit-testable, as the plan says; review only |
| MAC verified after decryption | killed | `the MAC is verified before any decryption is attempted` (decrypt call count), plus tamper and cross-session tests |
| single-use flag not set on success | killed | replay test, happy path |
| single-use flag set on MAC failure | killed | tamper, truncation, flooding, cross-session, ordering tests |
| window `>=` → `>` | killed | window boundary test |
| checksum takes the low 15 bits | killed | code vectors |
| responder skips explicit point validation | **survived, equivalent** | `Secp160r1Service.ecdhX` validates the peer key itself and returns null → `InvalidKey`; the explicit check only saves a scalar draw |
| envelope version byte not checked | killed | wrong-version test |

## Deviations from the plan, and why

- **§8 catch-rate bound.** The plan asks to assert a single-symbol catch rate "> 0.90 and < 1.0". That figure
  (31/32 ≈ 96.9%) describes the predecessor's 5-bit check. This format has a 15-bit checksum, so the expected miss
  rate is 2⁻¹⁵ and across the 5,580 tested substitutions there are provably none: the test asserts exact counts
  (checksum failures + version rejections = all mutations, no parse as another key) instead of a bound that could
  never hold.
- **Surrounding whitespace.** `CrockfordBase32.normalise` ignores dashes, spaces, tabs and underscores as the plan
  lists, but not newlines; `PairingCode.decode` trims the typed string first so a pasted trailing newline is
  accepted, as §8 requires.
- **Curve tests harness.** `CurveTest` runs as a kotest `StringSpec` (the only framework wired in this repo);
  every assertion is the tarball's, verbatim.
- **HMAC placement.** HKDF uses its own HMAC as the plan requires. The envelope MAC uses kryptom's `HmacService`:
  all platform implementations accept keys ≥ `minimumKeySize` (32 bytes for SHA-256), so a 32-byte `k_mac` is fine.
- **Hex helpers.** The tarball's `Hex.kt` was dropped in favour of kryptom's existing `hexToByteArray`/`toHexString`.

## Left open, deliberately

- AES-GCM in kryptom (§4) would let the protocol drop encrypt-then-MAC. Not part of this pass.
- Platform fast paths for the curve (§10.9). Not added; the interface is shaped for them.
- `PairingOffer` is not thread-safe; concurrent `accept` calls on one offer are the caller's problem, as documented.
