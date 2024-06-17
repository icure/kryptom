package com.icure.kryptom.crypto

import com.icure.kryptom.crypto.AesService.Companion.IV_BYTE_LENGTH
import com.icure.kryptom.crypto.AesService.Companion.aesEncryptedSizeFor
import com.icure.kryptom.utils.OpensslErrorHandling.ensureEvpSuccess
import com.icure.kryptom.utils.PlatformMethodException
import kotlinx.cinterop.CPointer
import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.addressOf
import kotlinx.cinterop.alloc
import kotlinx.cinterop.memScoped
import kotlinx.cinterop.pin
import kotlinx.cinterop.ptr
import kotlinx.cinterop.value
import libcrypto.EVP_CIPHER
import libcrypto.EVP_CIPHER_CTX_free
import libcrypto.EVP_CIPHER_CTX_new
import libcrypto.EVP_DecryptFinal_ex
import libcrypto.EVP_DecryptInit_ex
import libcrypto.EVP_DecryptUpdate
import libcrypto.EVP_EncryptFinal_ex
import libcrypto.EVP_EncryptInit_ex
import libcrypto.EVP_EncryptUpdate
import libcrypto.EVP_aes_128_cbc
import libcrypto.EVP_aes_256_cbc

@OptIn(ExperimentalForeignApi::class)
object OpensslAesService : AesService {
    override suspend fun <A : AesAlgorithm> generateKey(algorithm: A, size: AesService.KeySize): AesKey<A> =
        AesKey(
            OpensslStrongRandom.randomBytes(size.byteSize),
            algorithm
        )

    override suspend fun exportKey(key: AesKey<*>): ByteArray =
        key.rawKey.copyOf()

    override suspend fun <A : AesAlgorithm> loadKey(algorithm: A, bytes: ByteArray): AesKey<A> =
        AesKey(
            bytes.copyOf(),
            algorithm
        )

    override suspend fun encrypt(data: ByteArray, key: AesKey<*>, iv: ByteArray?): ByteArray {
        require (key.algorithm == AesAlgorithm.CbcWithPkcs7Padding) {
            "Unsupported aes algorithm: ${key.algorithm}"
        }
        if (iv != null) require(iv.size == IV_BYTE_LENGTH) {
            "Initialization vector must be $IV_BYTE_LENGTH bytes long (got ${iv.size})."
        }
        val cipher = validateKeyAndGetCipher(key)
        val ctx = EVP_CIPHER_CTX_new() ?: throw PlatformMethodException("Could not initialise context", null)
        val pinnedData = data.asUByteArray().pin()
        val rawKey = key.rawKey.asUByteArray().pin()
        val initialisedIv = (iv ?: OpensslStrongRandom.randomBytes(IV_BYTE_LENGTH)).asUByteArray().pin()
        val output = ByteArray(IV_BYTE_LENGTH + aesEncryptedSizeFor(data.size))
        val pinnedOutput = output.asUByteArray().pin()
        initialisedIv.get().copyInto(pinnedOutput.get()) // The IV is prepended to the output
        memScoped {
            val writtenBytes = alloc<Int>(0)
            var totalSize = 0
            try {
                EVP_EncryptInit_ex(
                    ctx,
                    cipher,
                    null,
                    rawKey.addressOf(0),
                    initialisedIv.addressOf(0),
                ).ensureEvpSuccess("EVP_EncryptInit_ex")
                EVP_EncryptUpdate(
                    ctx,
                    pinnedOutput.addressOf(IV_BYTE_LENGTH), // We have already prepended the IV
                    writtenBytes.ptr,
                    pinnedData.addressOf(0),
                    data.size
                ).ensureEvpSuccess("EVP_EncryptUpdate")
                totalSize += writtenBytes.value
                EVP_EncryptFinal_ex(
                    ctx,
                    pinnedOutput.addressOf(IV_BYTE_LENGTH + totalSize),
                    writtenBytes.ptr
                ).ensureEvpSuccess("EVP_EncryptFinal_ex")
                totalSize += writtenBytes.value
                check((totalSize + IV_BYTE_LENGTH) == output.size) {
                    "Unexpected size of output - Expected ${output.size} but got ${totalSize + IV_BYTE_LENGTH}"
                }
            } finally {
                pinnedData.unpin()
                rawKey.unpin()
                initialisedIv.unpin()
                pinnedOutput.unpin()
                EVP_CIPHER_CTX_free(ctx)
            }
        }
        return output
    }

    override suspend fun decrypt(ivAndEncryptedData: ByteArray, key: AesKey<*>): ByteArray {
        require (key.algorithm == AesAlgorithm.CbcWithPkcs7Padding) {
            "Unsupported aes algorithm: ${key.algorithm}"
        }
        val cipher = validateKeyAndGetCipher(key)
        val ctx = EVP_CIPHER_CTX_new() ?: throw PlatformMethodException("Could not initialise context", null)
        val pinnedInput = ivAndEncryptedData.asUByteArray().pin()
        val rawKey = key.rawKey.asUByteArray().pin()
        // This is a tiny bit too big, but better leave a bit of margin. Removing the IV length should still be fine
        val output = ByteArray(ivAndEncryptedData.size)
        val pinnedOutput = output.asUByteArray().pin()
        return memScoped {
            val writtenBytes = alloc<Int>(0)
            var totalSize = 0
            try {
                EVP_DecryptInit_ex(
                    ctx,
                    cipher,
                    null,
                    rawKey.addressOf(0),
                    pinnedInput.addressOf(0),
                ).ensureEvpSuccess("EVP_DecryptInit_ex")
                EVP_DecryptUpdate(
                    ctx,
                    pinnedOutput.addressOf(0),
                    writtenBytes.ptr,
                    pinnedInput.addressOf(IV_BYTE_LENGTH),
                    ivAndEncryptedData.size - IV_BYTE_LENGTH
                ).ensureEvpSuccess("EVP_DecryptUpdate")
                totalSize += writtenBytes.value
                check(totalSize < output.size) { "Output buffer was not big enough" }
                EVP_DecryptFinal_ex(
                    ctx,
                    pinnedOutput.addressOf(totalSize),
                    writtenBytes.ptr
                ).ensureEvpSuccess("EVP_DecryptFinal_ex")
                totalSize += writtenBytes.value
                check(totalSize < output.size) { "Output buffer was not big enough" }
                output.sliceArray(0 until totalSize)
            } finally {
                pinnedInput.unpin()
                rawKey.unpin()
                pinnedOutput.unpin()
                EVP_CIPHER_CTX_free(ctx)
            }
        }
    }

    private fun validateKeyAndGetCipher(key: AesKey<*>): CPointer<EVP_CIPHER> = checkNotNull(
        when (key.rawKey.size) {
            AesService.KeySize.Aes128.byteSize -> EVP_aes_128_cbc()
            AesService.KeySize.Aes256.byteSize -> EVP_aes_256_cbc()
            else -> throw IllegalArgumentException("Invalid size for key: ${key.rawKey.size}")
        }
    ) { "EVP cipher is null" }
}
