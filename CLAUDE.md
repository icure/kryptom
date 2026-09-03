# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

Kryptom is a Kotlin Multiplatform library (`com.icure.kryptom:kryptom`) exposing a single cryptographic API
(AES-CBC, RSA OAEP/PSS, HMAC, SHA-256/512, secure random, base64/base32/hex) backed by each platform's *native*
crypto library. There is one Gradle module, `lib`; `buildSrc` only holds plugin aliases and shared config
helpers (`configureAndroidLibrary`, `configureJvmTest`, `optInApple`).

Targets: JVM, Android, JS (browser + Node, ES modules), iOS (device + simulators), macOS (arm64), Linux (x64/arm64),
Windows (mingwX64).

## Commands

All tasks are on the `lib` module. Gradle 9.4.1 wrapper, Kotlin 2.3.20, kotest 6.1.11, Android KMP library plugin
(AGP 9.1.1). JDK 21 works; JVM bytecode target is 11.

```bash
./gradlew :lib:build                       # compile everything + run checks
./gradlew :lib:allTests                    # tests on every target buildable from this host

# Per-platform test tasks (the same commonTest suite runs against each native implementation)
./gradlew :lib:jvmTest
./gradlew :lib:testAndroidHostTest         # Android unit tests (JVM-hosted)
./gradlew :lib:jsNodeTest
./gradlew :lib:jsBrowserTest               # needs Chrome and Firefox installed (karma headless)
./gradlew :lib:iosSimulatorArm64Test       # or iosX64Test; simulator name from local.properties
./gradlew :lib:macosArm64Test
./gradlew :lib:linuxX64Test                # needs OpenSSL paths in local.properties (see below)
./gradlew :lib:mingwX64Test

# Single spec (kotest StringSpec). The trailing `.*` is required: a bare class name, a method-level
# pattern or a `*` without the dot silently runs zero tests (failOnNoMatchingTests is off). Check the
# JUnit XML under lib/build/test-results/jvmTest/ when in doubt; the console shows no PASSED lines.
./gradlew :lib:jvmTest --tests 'com.icure.kryptom.utils.Base64Test.*'
# One --tests pattern per invocation: with two patterns only one spec runs. Use a package pattern for several
# specs, and add --no-build-cache --rerun when re-running after editing main code (mutation-style checks).
./gradlew :lib:jvmTest --tests 'com.icure.kryptom.crypto.ec.*'

# Artifacts
./gradlew :lib:publishToMavenLocal         # works without signing properties
./gradlew :lib:assembleKryptomXCFramework  # iOS XCFramework
./gradlew :lib:jsNodeProductionLibraryDistribution   # JS lib + .d.ts
```

Test tasks are configured to print FAILED events with full stack traces and stdout; kotest 6 does not emit
per-test PASSED lines on the console, so a green build with no output is normal.

### local.properties (gitignored, in repo root)

Required for some targets; the build configures without it but those targets will fail to link/test:

```properties
sdk.dir=/Users/you/Library/Android/sdk        # Android
ios.simulator=iPhone 15 Pro                   # device id used by iOS test runs
cinteropsLibsDir=/opt/homebrew/opt/openssl@3/lib       # Linux target: libcrypto location
cinteropsIncludeDir=/opt/homebrew/opt/openssl@3/include # Linux target: openssl/*.h location
```

Browser tests may need `FIREFOX_BIN=/Applications/Firefox.app/Contents/MacOS/firefox`. Do not use `--offline` for
JS test tasks: kotest's JS engine pulls dependencies that are not in the cache until first fetched.

### Versions

Library version is `project.version` in `lib/build.gradle.kts`. Dependency versions live in
`gradle/libs.versions.toml`. Publishing to Maven Central requires `signing.*` properties; without them any remote
publish task fails on purpose.

## Architecture

### expect/actual around a single `CryptoService`

`commonMain` defines the whole public API as interfaces (`CryptoService` → `aes`, `rsa`, `hmac`, `digest`,
`strongRandom`) plus `expect val defaultCryptoService` and four `expect class` key wrappers (`PrivateRsaKey`,
`PublicRsaKey`, `AesKey`, `HmacKey`). Each platform source set supplies the `actual`s, wrapping its native key
type and delegating to the platform library:

| Source set           | Backend                                   | Key representation            |
|----------------------|-------------------------------------------|-------------------------------|
| `jvmAndAndroidMain`  | JCA with BouncyCastle provider registered | `java.security` / `SecretKey` |
| `commonMain/crypto/ec` | pure Kotlin secp160r1 (no platform has it)  | raw big-endian `ByteArray`s   |
| `jsMain`             | WebCrypto `SubtleCrypto` (browser, Node ≥19) | `dynamic` (CryptoKey)      |
| `appleMain`          | Security framework + CommonCrypto         | raw `ByteArray` (PKCS#1), converted per call to avoid `CFRelease` management |
| `linuxMain`          | OpenSSL libcrypto via cinterop            | RSA as PEM strings (PKCS#8 / SPKI), AES and HMAC as raw bytes |
| `mingwMain`          | Windows CNG (`BCrypt*`)                   | RSA as parsed `BCRYPT_RSAKEY_BLOB` Kotlin classes, AES and HMAC as raw bytes |

`jvmAndAndroidMain` is a custom intermediate source set (created in `lib/build.gradle.kts`); only
`initCryptoProvider()` differs between `jvmMain` and `androidMain`. `defaultCryptoServiceAvailable` (expect) tells
whether the platform default is usable at all (false on JS without WebCrypto). The Linux cinterop definition is
`lib/src/nativeInterop/cinterop/libcrypto.def`; OpenSSL return codes go through `OpensslErrorHandling`.
`-Xexpect-actual-classes` is enabled project-wide; Apple source sets opt into `ExperimentalForeignApi`.

The API is `suspend` throughout because WebCrypto is Promise-based; `StrongRandom` is the exception (sync).

`CryptoService.secp160r1` is the one member with a default body: it returns the pure-Kotlin
`PureKotlinSecp160r1Service` (x-only ECDH over secp160r1, ~80-bit security, for ephemeral keys in human-typed
pairing codes) fed by the platform `strongRandom`. `Fp160`/`Secp160r1` under `crypto/ec` are branch-free
field/curve arithmetic pinned to vectors from an independent Python reference in `tools/secp160r1-ref/`
(`secp160r1_ref.py` writes `vectors.json`, `gen_vectors_kt.py` regenerates `Secp160r1Vectors.kt`). Do not edit
those two files or their tests casually; if a curve test fails you broke something that was verified.
`HkdfSha256` (RFC 5869) builds on `DigestService.sha256` with its own HMAC because `HmacService` enforces a minimum
key size; `utils/constantTimeEquals` is for comparing MAC tags.

### Algorithms are types, keys are typed by algorithm

`Keys.kt` (common) models algorithms as sealed interfaces of `data object`s: `RsaAlgorithm` splits into
`RsaEncryptionAlgorithm` (OAEP SHA-1/SHA-256) and `RsaSignatureAlgorithm` (PSS SHA-256); `AesAlgorithm`
(CBC/PKCS7 only); `HmacAlgorithm` (SHA-1/256/512). Keys carry the algorithm as a type parameter, so e.g. `rsa.sign`
only accepts `PrivateRsaKey<RsaSignatureAlgorithm>` and misuse is a compile error.

Every algorithm has a string `identifier` with a `fromIdentifier` companion. These strings are the wire format
of the JS external interface and of JWK `alg` mapping; treat them as a stable contract.

AES-192 is intentionally unsupported (not available on every platform).

### JS external adapters

`jsMain/.../crypto/external/` defines `X*` `external interface`s (Promise-based, string algorithm ids, plain JS
key objects) and two adapters: `adaptExternalCryptoService` (JS impl → Kotlin `CryptoService`, used by
react-native/expo native crypto) and `adaptCryptoServiceForExternal` (Kotlin → TypeScript-friendly). External
implementations may be partial: `PartialXCryptoService`/`PartialXRsaService`/`PartialXStrongRandom` declare the
required subset and `completePartial*` functions fill the rest with Kotlin fallbacks (e.g. an absent `secp160r1`
falls back to the pure-Kotlin curve over the external random). Native errors are wrapped in
`ExternalCryptoServiceException`. `@JsExport` was deliberately removed from the codebase; the JS build uses
`binaries.library()` + generated TS definitions. When the common API changes, both adapter directions, the `X*`
interfaces and the `completePartial*` object literals must change with it.

### Pure-Kotlin common code

`crypto/asn/` is a minimal ASN.1 reader/writer used for PKCS#1 ↔ PKCS#8 ↔ SPKI conversion and JWK ↔ DER
(`AsnToJwkConverter`). It is deliberately narrow; do not treat it as a general ASN.1 library. `FormatUtils.kt`
exposes the format conversions publicly. `utils/` holds Base64 (with URL-safe and missing-padding handling),
Base32 and hex helpers.

### Testing model

All tests live in `commonTest` (kotest `StringSpec`) and call `defaultCryptoService`, so running a platform's
test task is what validates that platform's native implementation. Tests mix round-trip checks with fixed test
vectors (known key + IV → expected ciphertext/signature/digest) that guarantee cross-platform interoperability.
Test data is embedded in `CryptoTestData.kt` because file loading is impractical in browser tests; some strings
there have significant trailing whitespace that tests depend on.

### Adding or changing a primitive

Change the common interface and `Keys.kt`, then implement in every platform source set (`jvmAndAndroidMain`,
`jsMain` + its `external/` adapters, `appleMain`, `linuxMain`, `mingwMain`), and add common tests including
fixed vectors. A change that compiles on one target is not done until it compiles on all of them;
`./gradlew :lib:publishToMavenLocal` is a convenient "compile everything" check once `local.properties` is set.

## Plans

`docs/plans/` holds implementation plans for in-progress features. Read the relevant plan fully before working
on that feature.
