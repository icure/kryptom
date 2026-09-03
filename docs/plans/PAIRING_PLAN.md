# Implementation plan: 36-character human-typed pairing codes (secp160r1, x-only)

**Audience:** a Claude Code session working inside the `kryptom` repository.
**Status (2026-09-03):** implemented. The primitives live in kryptom (`com.icure.kryptom.crypto.ec`,
`HkdfSha256`, `constantTimeEquals`, exposed as `CryptoService.secp160r1`; Python reference and vector generator in
`tools/secp160r1-ref/`). The pairing scheme (code format, protocol, tests) lives in the consuming application,
cardinal-sdk, under `com.icure.cardinal.sdk.crypto.pairing`, as §4 prescribes. Sections below are the original
specification and remain the reference for the format and protocol.

---

## 1. What this is for

Two parties pair over an asymmetric channel pair:

- **A → B** is out-of-band, authentic, and tiny: A renders a code on screen, a human types it
  into B. There is **no** network path from A to B.
- **B → A** is a one-way network channel carrying arbitrary bytes.

B must deliver a secret to A such that only A can read it. The typed code must be safe to
eavesdrop — someone reading it off the screen or over a shoulder must gain nothing.

**The secret has no value after five minutes.** This was confirmed explicitly and the whole
security argument depends on it (see §2.3). If that ever stops being true, the curve choice must be
revisited before anything else.

### Why the code carries a public key, and not a hash of one

The obvious improvement — display a short fingerprint and send the real key over the network — is
unavailable, because there is no A → B network channel. The key itself must fit in the typed code.
Do not "optimise" the design back to a fingerprint; it was considered and ruled out by the channel
topology.

### Why not a hash-commitment / one-time-code scheme

A previous iteration used a hash commitment (verifier stores `H(code)`, human types the preimage).
That is strictly shorter — 20 characters for 2^95 — but the code is then a **bearer token**: anyone
who reads it can authenticate in the target's place. That was the requirement that killed it. Do
not reintroduce it. Only these four files carry over from that work:
`CrockfordBase32.kt`, `ConstantTime.kt`, `Hex.kt`, and the test-harness technique in §8.

---

## 2. Security rationale — read before changing any parameter

### 2.1 Why 160 bits and not 100

A displayed EC public key of *L* bits gives *L/2* bits of security, because the attacker recovers
the private key by Pollard rho in ~2^(L/2) group operations rather than guessing anything. At 100
bits (a 20-character code) that is **2^50** — about 1.1×10^15 point operations, reachable in five
minutes with a few thousand GPUs, i.e. a few thousand dollars of spot capacity. At 160 bits it is
2^80 ≈ 1.2×10^24, which is ~14 days even at an implausible 10^18 ops/sec: a margin of roughly
4,000× against the five-minute window.

This halving is the crucial asymmetry versus a hash-based code, where security is *linear* in the
typed bits. It is why 20 characters was enough for the old scheme and is nowhere near enough here.

### 2.2 What 2^80 does *not* buy

The displayed key is public and recordable forever. 2^80 is not a forever number — RSA-768 took
~2^67 of real effort. The margin above is against a *five-minute* deadline, nothing longer.
Consequences that are load-bearing, not stylistic:

- **Keys must be ephemeral per pairing and never reused.** A long-lived key at 2^80 eventually
  justifies the attack.
- **Nothing durable may be derived from the transported secret.** If it ever becomes a device key
  or seeds a long-term session, 2^80 must hold for that secret's whole lifetime and 160 bits is the
  wrong choice — move to P-256 and a 56-character code.

### 2.3 What this design does not protect

**B is not authenticated to A.** Anyone can encrypt to a public key, so A cannot tell whether the
envelope came from B or from someone who read the screen. Only A's identity is established (only A
holds the private key). No key length changes this. If A needs to know who sent the secret, that is
a separate mechanism and a separate conversation.

**A passive observer who also controls the network can substitute their own envelope.** A will then
accept a secret chosen by the attacker rather than by B. Again: not fixable within this topology.

Both are acceptable for pairing-style flows. Write them down in the public API docs so a future
caller does not assume otherwise.

### 2.4 Implementation risk dominates

At 2^80 the discrete log is not the threat; a carry bug or a timing leak in hand-written field
arithmetic is. secp160r1 has no support in WebCrypto, CryptoKit, or Windows CNG, which is why this
plan ships a pure-Kotlin implementation rather than platform bindings. Treat §8 (testing) and §9
(mutation testing) as part of the deliverable, not as optional polish.

---

## 3. Status: what is already built and verified

A tarball accompanies this plan with working, tested code. Start from it.

| Component | File | Status |
|---|---|---|
| Crockford base32 codec | `CrockfordBase32.kt` | done, tested |
| Constant-time compare | `ConstantTime.kt` | done, tested |
| Hex helpers | `Hex.kt` | done, tested |
| F_p arithmetic, p = 2^160-2^31-1 | `Fp160.kt` | **done, 26/26 tests green** |
| secp160r1 points, ladder, x-only ECDH | `Secp160r1.kt` | **done, 26/26 tests green** |
| Known-answer vectors | `Vectors.kt` (generated) | done |
| Curve test suite | `CurveTest.kt` | done |
| Python reference + vector generator | `ref/secp160r1_ref.py` | done |
| 36-symbol code format | `PairingCode.kt` (cardinal-sdk) | done, tested |
| HMAC-SHA256 + HKDF-SHA256 | `HkdfSha256.kt` (kryptom) | done, RFC 4231 / RFC 5869 / reference vectors |
| Pairing protocol, both sides | `Pairing.kt` (cardinal-sdk) | done, tested |
| Format + protocol tests | `PairingCodeTest.kt`, `PairingProtocolTest.kt` (cardinal-sdk) | done |
| Mutation testing pass | — | run; see the implementation report for the kill table |

### How the curve layer was verified

1. Domain parameters asserted against their definitions (p = 2^160-2^31-1, p ≡ 3 mod 4, a = -3,
   G on the curve, n prime-order 161 bits, non-zero discriminant).
2. A Python reference was written, then cross-checked against `python-ecdsa`'s `SECP160r1`:
   **19/19** scalar multiplications, **6/6** ECDH exchanges, **13/13** point-validity decisions
   agreed.
3. The Jacobian formulas (`dbl-2001-b` for a = -3, `add-1998-cmo-2`) and the completeness selection
   logic were validated **in Python first**, over 200 randomised cases with random projective
   rescaling plus every degenerate case (∞+∞, ∞+G, G+∞, G+G, G+(−G), 2G+(−2G), dbl(∞)), before
   being ported. This is why `addComplete` can be trusted.
4. The Kotlin port is pinned to the same vectors and passes 26/26.

**Performance (JVM, for budgeting):** `publicKeyX` ≈ 2.9 ms, `ecdhX` ≈ 2.5 ms. Expect 10–30× that
on Kotlin/JS where `Long` is emulated, so roughly 30–90 ms. Both are one-shot per pairing, so this
is fine; add a benchmark if you want to track it.

---

## 4. Where the code should live

Two distinct concerns — keep the boundary clean:

**Primitives → kryptom.** The curve, HKDF, and the constant-time comparison are general-purpose and
belong in kryptom. kryptom currently has **no elliptic-curve support at all** (only RSA, AES-CBC,
HMAC, digests), so this is a genuine addition, not a modification.

- `Fp160.kt`, `Secp160r1.kt` → new package, e.g. `com.icure.kryptom.crypto.ec`.
  Note the departure from kryptom's `expect`/`actual` convention: this is a single pure-`commonMain`
  implementation, because no platform provides secp160r1. Expose it behind an interface shaped for
  future platform delegation (BouncyCastle on JVM/Android, OpenSSL via the existing libcrypto
  cinterop on native) so a fast path can be added later without an API break. Do **not** add the
  platform paths now — one implementation with one test surface is the safer starting point.
- `constantTimeEquals` → `com.icure.kryptom.utils`. kryptom has hex/base64/base32 helpers and
  digests but nothing for comparing secret-derived bytes, and every HMAC or commitment verifier
  needs it. A later platform-delegating version could route to `MessageDigest.isEqual` (JVM),
  `crypto.timingSafeEqual` (Node), `OPENSSL_memcmp` (native).
- `Hkdf` (HKDF-SHA256, RFC 5869) → `com.icure.kryptom.crypto`. Build it on `DigestService.sha256`
  with an internal HMAC, **not** on `HmacService`: `HmacAlgorithm.HmacSha256.recommendedKeySize` is
  64 bytes and the interface documents that some platforms only accept the recommended size, which
  HKDF's 32-byte PRK would violate.
- **Worth raising separately:** kryptom's AES is CBC/PKCS7 only. Adding AES-GCM would let this
  protocol drop encrypt-then-MAC entirely, and is useful well beyond this feature.

**The pairing scheme itself is application-level** — the wire format, the version byte, the
five-minute policy, the one-shot rule. It should not live in a general crypto library. Put it in its
own module (`pairing/`) or in the consuming application. Flag this to the human if the repo layout
makes the choice non-obvious.

---

## 5. Wire format: the 36-symbol code

```
VYD5-EFGR-54DN-YVWP-HGJ7-M4J9-H14G-0H2A-TQ4A
```

36 Crockford base32 symbols, displayed as 9 dash-separated groups of 4.

| Symbols | Bits | Content |
|---|---|---|
| 0 | 5 | version, big-endian; v1 = `1` |
| 1..32 | 160 | x-coordinate of A's public key, big-endian |
| 33..35 | 15 | checksum, big-endian |

Every field is a whole number of symbols and 160 bits is exactly 32 symbols, so there is **no
padding anywhere** — encode the x-coordinate as 4 blocks of 5 bytes, each block becoming 8 symbols
most-significant-first. Keep it that way; a format with padding bits invites a class of bugs this
one cannot have.

**Alphabet:** `0123456789ABCDEFGHJKMNPQRSTVWXYZ` — no `I`, `L`, `O`, `U`.

**Parsing rules** (already implemented in `CrockfordBase32.normalise`):
- case-insensitive;
- `O`/`o` → `0`; `I`/`i`/`L`/`l` → `1`;
- `U`/`u` is **rejected, not folded** — folding it would silently accept a code never issued;
- `-`, space, tab, en/em dash and `_` are ignored, so grouping is optional and regrouping is fine;
- require exactly 36 symbols after normalisation.

**Checksum:**

```
checksum = (be16(SHA-256(LP("com.icure.pairing.v1.code", versionByte, xBytes))[0..1])) >> 1
```

i.e. the top 15 bits of the digest. `LP` is length-prefixed concatenation: each field preceded by
its length as 4 bytes big-endian. **Plain concatenation is a bug** — it makes
`(domain="ab", action="c")` and `(domain="a", action="bc")` hash identically, which is how domain
separation quietly stops separating. There is a test for this; keep it.

Detection rate is 31/32 per symbol-class ≈ 96.9% overall, measured at 96.92% across 37,200
single-symbol mutations in the predecessor scheme. Good enough, and it catches multi-character
errors at the same rate. If you want a *guarantee* for single errors and adjacent transpositions
instead, that is a Damm order-32 quasigroup and a 1024-entry table — not recommended, and not worth
the table's validation burden.

Verify the checksum **before** the curve work, so a typo costs no scalar multiplication and reports
as "check what you typed" rather than "rejected".

---

## 6. Protocol

### 6.1 Flow

**Initiator A (displays the code):**

1. `dA ← randomScalar()`; `xA ← publicKeyX(dA)`.
2. Emit `code = encode(version = 1, xA)`; display it.
3. Record `notBefore = now`, `notAfter = now + 5 min`. Keep `dA` and `xA`.
4. On receiving an envelope: check the window, check not already accepted, verify, decrypt.
5. **Accept exactly one envelope**, then wipe `dA` and refuse everything afterwards.

**Responder B (types the code):**

1. Normalise and parse the typed code; check the version and checksum.
2. `decompress(xA)` — reject if not on the curve.
3. `dB ← randomScalar()`; `xB ← publicKeyX(dB)`.
4. `shared ← ecdhX(dB, xA)`.
5. Derive keys (§6.2), encrypt, MAC, send the envelope.

x-only works because ±P share an x and ±kP share an x, so both sides reach the same shared
x-coordinate regardless of which root each reconstructed. `decompress` picks the even root
deterministically so the transcript agrees.

### 6.2 Key derivation

```
transcript = LP("com.icure.pairing.v1.kdf", versionByte, xA, xB)
ikm        = shared                       (20 bytes, the ECDH x-coordinate)
PRK        = HMAC-SHA256(key = 32 zero bytes, msg = ikm)
OKM        = T1 || T2,  Ti = HMAC-SHA256(PRK, T(i-1) || transcript || byte(i))
k_enc      = OKM[0..31]      (AES-256)
k_mac      = OKM[32..63]     (HMAC-SHA256)
```

Standard RFC 5869 with an empty salt and the transcript as `info`. Vectors for this are in
`Vectors.kdf` — three cases, generated by the Python reference. Match them exactly.

Binding **both** public keys and the version into the transcript is what stops cross-session and
cross-version replay. Do not reduce the transcript to just the shared secret.

### 6.3 Envelope

```
envelope = versionByte(1) || xB(20) || ivAndCiphertext || mac(32)
mac      = HMAC-SHA256(k_mac, versionByte || xB || ivAndCiphertext)
```

`ivAndCiphertext` is exactly what `AesService.encrypt` returns (kryptom prepends the IV).
Encrypt-then-MAC: **verify the MAC with `constantTimeEquals` before attempting to decrypt.**

A's acceptance rule matters for a concern raised explicitly during design: A must accept **the first
envelope whose MAC verifies**, not the first envelope that arrives. Otherwise an attacker who cannot
decrypt anything still wins by flooding A with garbage that consumes the single-use slot.

### 6.4 API shape

Suspend functions throughout, since kryptom's digest and AES are suspend. Sketch:

```kotlin
class PairingInitiator(crypto: CryptoService = defaultCryptoService) {
    suspend fun begin(nowEpochMs: Long, ttlMillis: Long = FIVE_MINUTES): PairingOffer
    suspend fun accept(offer: PairingOffer, envelope: ByteArray, nowEpochMs: Long): AcceptResult
}

class PairingResponder(crypto: CryptoService = defaultCryptoService) {
    suspend fun respond(typedCode: String, secret: ByteArray): RespondResult
}
```

Return sealed results rather than throwing, mirroring the predecessor's `VerificationResult`:
`Accepted(secret)`, `Malformed(reason)`, `ChecksumFailed`, `UnknownVersion`, `InvalidKey`,
`MacFailed`, `Expired`, `NotYetValid`, `AlreadyUsed`. Take `nowEpochMs` as a parameter — do **not**
read a clock inside the library. An offline verifier cannot enforce a five-minute window without a
trusted monotonic time source, and whether it has one is a property of the device. Making it a
parameter keeps that dependency visible and the window testable.

---

## 7. Task order

1. `Hkdf.kt` — HMAC-SHA256 over `DigestService.sha256`, then HKDF. Test against `Vectors.kdf`
   **and** against the RFC 5869 test vectors (add those; they are not in the generated file).
2. `PairingCode.kt` — encode/decode per §5. Test against `Vectors.codes` (5 cases with expected
   36-symbol strings).
3. `Pairing.kt` — both sides per §6.
4. Test suites per §8.
5. Mutation pass per §9.
6. Only then consider platform fast paths, benchmarks, or API polish.

Do steps 1–3 without touching `Fp160.kt` or `Secp160r1.kt`. If a curve test starts failing, you
have broken something that was green; revert rather than adjusting the test.

---

## 8. Test plan

Keep `CurveTest.kt` as-is and add:

**Format**
- round-trip encode/decode for every vector in `Vectors.codes`, including the exact expected string;
- typed-variant acceptance: as displayed, no dashes, lowercased, spaces for dashes, surrounding
  whitespace, regrouped in 2s;
- ambiguous glyphs: force a code containing `0` and `1`, retype as `O` and lowercase `l`, must
  still parse to the same key;
- `U` rejected as malformed;
- wrong length (35, 37, 0) malformed;
- character outside the alphabet malformed;
- exhaustive single-symbol substitution: must **never** parse to a different valid key without the
  checksum failing; assert the catch rate is > 0.90 and < 1.0;
- adjacent transposition: never silently accepted;
- unknown version symbol rejected distinctly from a bad checksum.

**Protocol**
- happy path: A begins, B responds, A accepts, secret matches byte-for-byte;
- both sides derive the same keys when B reconstructs the odd root (patch `decompress`'s choice in a
  test double, or assert via `ecdhX` on the negated point as `CurveTest` already does);
- **tamper tests, one per field:** flip a byte in `xB`, in the IV, in the ciphertext, in the MAC —
  each must return `MacFailed` and must **not** consume the single-use slot;
- truncated and over-long envelopes rejected;
- wrong version byte in the envelope rejected;
- replay: the same envelope twice → `Accepted` then `AlreadyUsed`;
- flooding: garbage envelopes before the real one must not consume the slot, and the real one must
  still be accepted afterwards;
- cross-session: an envelope built for offer #1 must fail against offer #2 (transcript binding);
- window: `notBefore - 1` → `NotYetValid`; `notAfter` → `Expired`; `notAfter - 1` → `Accepted`;
  default TTL is exactly 5 min;
- an envelope whose `xB` is not on the curve → `InvalidKey`, not a crash;
- a code whose `xA` is not on the curve (checksum recomputed to match, so it passes the checksum) →
  `InvalidKey`. **Generate this deliberately**; it is the case where skipping point validation would
  otherwise go unnoticed.

**Randomness**
- 400 pairings produce 400 distinct codes;
- symbol distribution over the x-coordinate portion is roughly uniform (a loose 0.5×–1.5× band
  around the mean catches a stuck or modulo-biased generator without being flaky);
- `randomScalar` rejects all-zero draws rather than returning them.

---

## 9. Mutation testing — required, not optional

After the suite is green, break the implementation deliberately and confirm the tests catch it. This
is how a real gap was found in the predecessor scheme: a test named
`codeIsBoundToItsAction` passed *even with the action removed from the digest*, because the store's
own filter meant the mismatched record was never offered for comparison. The binding that mattered
was untested and the test name actively misled. Two tests were added, one using a store that
deliberately ignores the filter.

Mutants to run at minimum — each must be killed, and note *which* test kills it:

| Mutation | Should be caught by |
|---|---|
| point validation removed from `decompress` | the deliberate off-curve `xA` test |
| `lessThanPMask` check dropped (accept x ≥ p) | non-canonical encoding test |
| checksum verification removed | single-symbol substitution test |
| length-prefixing replaced by plain concatenation | transcript ambiguity test |
| `xB` dropped from the transcript | cross-session test |
| version dropped from the transcript | wrong-version test |
| MAC compared with `==` instead of constant-time | no test will catch this — see below |
| MAC verified *after* decryption | ordering test (assert decrypt is not reached) |
| single-use flag not set on success | replay test |
| single-use flag set on MAC failure | flooding test |
| window `>=` → `>` | window boundary test |
| `mulSmall(x, 8)` → `mulSmall(x, 4)` in `jDouble` | scalar multiplication vectors |
| `addComplete` precedence reordered | degenerate-case tests |
| random mask narrowed (e.g. 20 bits → 16) | uniformity test |

Two honest caveats on that table. Constant-time behaviour is **not testable** by unit tests — it
needs review, and on JVM/JS it is best-effort regardless because the JIT may introduce branches and
`Long` is emulated on JS. And a mutant that "survives" may mean the mutation was ineffective rather
than that the test is weak: in the predecessor pass, one surviving mutant turned out to have zeroed
length-prefix bytes while still leaving 4-byte gaps, which preserved the separation it was meant to
destroy. Check what the mutation actually did before concluding the suite is at fault.

---

## 10. Decisions that must not be silently changed

If you think one of these is wrong, say so and stop — do not just implement the alternative.

1. **x-only keys, no sign bit.** This is what makes the key exactly 32 symbols.
2. **Crockford, not RFC 4648** (`base32Encode` in kryptom). RFC 4648 keeps `I`, `L`, `O`, `U`.
3. **Point validation in `decompress` is mandatory.** The x-coordinate comes from a keyboard.
4. **Length-prefixed digest inputs**, everywhere.
5. **Ephemeral keys, one pairing each.** Required by the 2^80 choice (§2.2).
6. **One accepted envelope per offer, chosen by MAC validity, not arrival order.**
7. **`nowEpochMs` is a parameter, not a clock read.**
8. **The 5-bit version symbol stays.** It is the escape hatch for moving to P-256 later.
9. **Do not add platform fast paths in this pass.**

---

## 11. Definition of done

- [ ] All curve tests still green (26/26), untouched.
- [ ] HKDF matches both `Vectors.kdf` and the RFC 5869 vectors.
- [ ] Code format matches all 5 entries of `Vectors.codes`, string-for-string.
- [ ] Full protocol suite green, including every tamper and window case in §8.
- [ ] Mutation pass run, every mutant in §9 accounted for, surviving mutants explained.
- [ ] `constantTimeEquals`, `Hkdf`, and the curve landed in kryptom with the pairing scheme outside
      it (§4), or the human has agreed to a different boundary.
- [ ] Public API docs state plainly that B is not authenticated to A (§2.3) and that the secret must
      not outlive five minutes (§2.2).
- [ ] Compiles for every target kryptom declares. The code is pure `commonMain` with no
      `expect`/`actual`, so this should be free — confirm rather than assume, especially JS.

---

## Appendix A: regenerating the vectors

`ref/secp160r1_ref.py` is the generator. It asserts the domain parameters against their definitions
on every run and refuses to emit vectors if the reference's own ECDH disagrees with itself.

```
python3 ref/secp160r1_ref.py          # writes vectors.json
```

Then regenerate `Vectors.kt` from the JSON. Keep the cross-check against `python-ecdsa`
(`pip install ecdsa`) in the loop when you touch the reference — it is the only thing standing
between a subtle reference error and a confidently wrong implementation.

## Appendix B: running tests without Maven access

Inside kryptom you have Gradle and a working dependency graph, so use them. If you ever need to
compile Kotlin in a sandbox where Maven Central is blocked: JetBrains publish the compiler on npm
(`npm i kotlin-compiler`), whose `lib/` also contains `kotlin-test.jar` and
`kotlin-test-junit.jar`; JUnit 4 and Hamcrest ship inside `$GRADLE_HOME/lib`. That combination
compiles and runs a `kotlin.test` suite via `org.junit.runner.JUnitCore` with no network at all.
That is how the curve layer in this plan was verified.
