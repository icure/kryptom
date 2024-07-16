package com.icure.kryptom.crypto

import com.icure.kryptom.utils.OpensslErrorHandling.ensureEvpSuccess
import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.addressOf
import kotlinx.cinterop.alloc
import kotlinx.cinterop.memScoped
import kotlinx.cinterop.pin
import kotlinx.cinterop.ptr
import kotlinx.cinterop.value
import libcrypto.EVP_DigestSignInit
import libcrypto.EVP_MAX_MD_SIZE
import libcrypto.EVP_sha256
import libcrypto.EVP_sha512
import libcrypto.HMAC_CTX_free
import libcrypto.HMAC_CTX_new
import libcrypto.HMAC_Final
import libcrypto.HMAC_Init_ex
import libcrypto.HMAC_Update

@OptIn(ExperimentalForeignApi::class)
object OpensslHmacService : HmacService {
    override suspend fun <A : HmacAlgorithm> generateKey(algorithm: A, keySize: Int?): HmacKey<A> {
        require(keySize == null || keySize >= algorithm.minimumKeySize) {
            "Invalid key size for $algorithm. A minimal length of ${algorithm.minimumKeySize} is required"
        }
        return HmacKey(OpensslStrongRandom.randomBytes(keySize ?: algorithm.recommendedKeySize), algorithm)
    }

    override suspend fun exportKey(key: HmacKey<*>): ByteArray =
        key.rawKey

    override suspend fun <A : HmacAlgorithm> loadKey(algorithm: A, bytes: ByteArray): HmacKey<A> {
        require(bytes.size >= algorithm.minimumKeySize) {
            "Invalid key length for algorithm $algorithm: got ${bytes.size} but at least ${algorithm.minimumKeySize} expected"
        }
        return HmacKey(bytes.copyOf(), algorithm)
    }

    override suspend fun sign(data: ByteArray, key: HmacKey<*>): ByteArray {
        require(key.algorithm == HmacAlgorithm.HmacSha512 || key.algorithm == HmacAlgorithm.HmacSha256) {
            "Unsupported hmac algorithm: ${key.algorithm}"
        }
        val ctx = HMAC_CTX_new()
        val rawKey = key.rawKey.asUByteArray().pin()
        val pinnedData = data.asUByteArray().pin()
        val output = ByteArray(EVP_MAX_MD_SIZE)
        val pinnedOutput = output.asUByteArray().pin()
        return memScoped {
            val writtenBytes = alloc(0.toUInt())
            try {
                HMAC_Init_ex(
                    ctx,
                    rawKey.addressOf(0),
                    key.rawKey.size,
                    EVP_sha512(),
                    null
                ).ensureEvpSuccess("HMAC_Init_ex")
                HMAC_Update(
                    ctx,
                    pinnedData.addressOf(0),
                    data.size.toULong()
                ).ensureEvpSuccess("HMAC_Update")
                HMAC_Final(
                    ctx,
                    pinnedOutput.addressOf(0),
                    writtenBytes.ptr
                ).ensureEvpSuccess("HMAC_Final")
                check(writtenBytes.value <= EVP_MAX_MD_SIZE.toULong()) {
                    "Unexpected amount of bytes written"
                }
                output.sliceArray(0 until writtenBytes.value.toInt())
            } finally {
                rawKey.unpin()
                pinnedData.unpin()
                pinnedOutput.unpin()
                HMAC_CTX_free(ctx)
            }
        }
    }

    override suspend fun verify(signature: ByteArray, data: ByteArray, key: HmacKey<*>): Boolean {
        val currentSignature = sign(data, key)
        return signature.contentEquals(currentSignature)
    }
}
