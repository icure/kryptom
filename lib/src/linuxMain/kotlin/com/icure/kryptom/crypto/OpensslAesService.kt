package com.icure.kryptom.crypto

import com.icure.kryptom.crypto.AesService.Companion.IV_BYTE_LENGTH
import com.icure.kryptom.crypto.AesService.Companion.aesEncryptedSizeFor
import com.icure.kryptom.utils.OpensslErrorHandling.ensureEvpSuccess
import com.icure.kryptom.utils.PlatformMethodException
import kotlinx.cinterop.CPointer
import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.Pinned
import kotlinx.cinterop.addressOf
import kotlinx.cinterop.alloc
import kotlinx.cinterop.memScoped
import kotlinx.cinterop.pin
import kotlinx.cinterop.ptr
import kotlinx.cinterop.usePinned
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
import libcrypto.EVP_aes_128_ctr
import libcrypto.EVP_aes_256_cbc
import libcrypto.EVP_aes_256_ctr

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

    override suspend fun decrypt(
        encryptedData: ByteArray,
        key: AesKey<*>,
        iv: ByteArray
    ): ByteArray {
        require(iv.size == IV_BYTE_LENGTH) { "IV must be 16 bytes long" }
        return encryptedData.asUByteArray().usePinned { pinnedEncryptedData ->
            iv.asUByteArray().usePinned { pinnedIv ->
                doDecrypt(
                    key,
                    pinnedEncryptedData,
                    0,
                    encryptedData.size,
                    pinnedIv
                )
            }
        }
    }

    override suspend fun decrypt(ivAndEncryptedData: ByteArray, key: AesKey<*>): ByteArray {
        return ivAndEncryptedData.asUByteArray().usePinned { pinnedData ->
            doDecrypt(
                key,
                pinnedData,
                IV_BYTE_LENGTH,
                ivAndEncryptedData.size - IV_BYTE_LENGTH,
                pinnedData
            )
        }
    }

    private fun doDecrypt(
        key: AesKey<*>,
        pinnedEncryptedData: Pinned<UByteArray>,
        encryptedDataOffset: Int,
        encryptedDataSize: Int,
        pinnedIv: Pinned<UByteArray>,
    ): ByteArray {
        val cipher = validateKeyAndGetCipher(key)
        // This is a tiny bit too big, but better leave a bit of margin.
        val output = ByteArray(encryptedDataSize)
        val ctx = EVP_CIPHER_CTX_new() ?: throw PlatformMethodException("Could not initialise context", null)
        val rawKey = key.rawKey.asUByteArray().pin()
        val pinnedOutput = output.asUByteArray().pin()
        return memScoped {
            try {
                val writtenBytes = alloc<Int>(0)
                var totalSize = 0
                EVP_DecryptInit_ex(
                    ctx,
                    cipher,
                    null,
                    rawKey.addressOf(0),
                    pinnedIv.addressOf(0),
                ).ensureEvpSuccess("EVP_DecryptInit_ex")
                EVP_DecryptUpdate(
                    ctx,
                    pinnedOutput.addressOf(0),
                    writtenBytes.ptr,
                    pinnedEncryptedData.addressOf(encryptedDataOffset),
                    encryptedDataSize
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
                rawKey.unpin()
                pinnedOutput.unpin()
                EVP_CIPHER_CTX_free(ctx)
            }
        }
    }

    private fun validateKeyAndGetCipher(key: AesKey<*>): CPointer<EVP_CIPHER> {
        val is256 = when (key.rawKey.size) {
            AesService.KeySize.Aes128.byteSize -> false
            AesService.KeySize.Aes256.byteSize -> true
            else -> throw IllegalArgumentException("Invalid size for key: ${key.rawKey.size}")
        }
        return checkNotNull(
            when (key.algorithm) {
                AesAlgorithm.CbcWithPkcs7Padding -> if (is256) EVP_aes_256_cbc() else EVP_aes_128_cbc()
                AesAlgorithm.CtrWithPkcs7Padding -> if (is256) EVP_aes_256_ctr() else EVP_aes_128_ctr()
            }
        ) { "EVP cipher is null" }
    }
}
