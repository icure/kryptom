# Kryptom - kotlin crypto multiplatform

Provides access from kotlin multiplatform to:
- Native cryptographic primitives and digest algorithms including:
  - Secure random
  - Aes encryption
  - Rsa encryption and signing
  - Hmac signing
- Byte array encoding and decoding (hex, base64)

## Using the dependency

The library is published on maven. If you want to build your project also for linux you may need to modify your gradle
configuration, depending on your system configuration.

You may need for example to add the following configuration

```kotlin
linuxX64 {
  binaries {
    all {
      /*
       * Tell the compiler where it can find openssl's libcrypto
       * 
       * Solves errors like:
       * error: cannot find -lcrypto
       * error: undefined reference to 'EVP_CIPHER_CTX_new'
       */
      linkerOpts.add("-L/path/to/shared/libs/directory") // e.g. /usr/lib
      /*
       * Currently the most recent version of openssl's libcrypto uses glibc methods that are not available in the version
       * used by kotlin native build tool. You can use these arguments to ignore linking errors and your project will run
       * anyway as long as you have installed a recent version of gcc on your system.
       * 
       * Solves errors like:
       * error: undefined reference to 'x@GLIBC_2.34'
       */
      freeCompilerArgs += listOf("-linker-option", "--allow-shlib-undefined")
    }
  }
}
```

## Building the project

You need to create a local properties file in the root of the project with the following properties:

```properties
# Path to the android sdk, by default on mac /Users/you/Library/Android/sdk
sdk.dir=/path/to/android/sdk
# Name of ios simulator to use for testing, e.g. iPhone 13 Pro Max
ios.simulator=iPhone name
# Path to the directory containing openssl libcrypto library
cinteropsLibsDir=/usr/lib
# Path to the directory containing openssl/*.h files
cinteropsIncludeDir=/usr/include
```

### Building linux library on mac

The openssl library path on mac varies depending on how you installed openssl. For example if you used brew you could need
the following properties.
```properties
# Path to the directory containing openssl libcrypto library
cinteropsLibsDir=/opt/homebrew/Cellar/openssl@3/3.3.0/lib
# Path to the directory containing openssl/*.h files
cinteropsIncludeDir=/opt/homebrew/Cellar/openssl@3/3.3.0/include
```

## Testing

Unit tests can run on all target platforms (jvm, js browser, js node, ios, android) using the various gradle `[platform]Test` tasks, or using the `allTests` task.

E2e tests are currently only available on the jvm platform, as the test setup library is not yet available for the other platforms.

### Browser tests

Currently the project is configured to do browser tests on Chrome and Firefox. You will need to have the browsers installed on your machine.

You may also need to specify the location of their executables through environment variables, such as:

```
FIREFOX_BIN=/Applications/Firefox.app/Contents/MacOS/firefox
```


