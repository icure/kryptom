package com.icure.kryptom.crypto

import com.icure.kryptom.utils.PlatformMethodException
import com.icure.kryptom.utils.ensureSuccess
import kotlinx.cinterop.alloc
import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.addressOf
import kotlinx.cinterop.memScoped
import kotlinx.cinterop.pin
import kotlinx.cinterop.ptr
import kotlinx.cinterop.reinterpret
import kotlinx.cinterop.usePinned
import kotlinx.cinterop.value
import platform.windows.BCRYPT_ALG_HANDLE
import platform.windows.BCRYPT_HASH_HANDLEVar
import platform.windows.BCryptCreateHash
import platform.windows.BCryptDestroyHash
import platform.windows.BCryptFinishHash
import platform.windows.BCryptHashData

@OptIn(ExperimentalForeignApi::class)
object BCryptHmacService : HmacService {
    // https://github.com/tpn/winsdk-10/blob/9b69fd26ac0c7d0b83d378dba01080e93349c2ed/Include/10.0.14393.0/shared/bcrypt.h#L884C8-L884C59
    private const val BCRYPT_ALG_HANDLE_HMAC_FLAG = 0x08

    override suspend fun <A : HmacAlgorithm> generateKey(algorithm: A): HmacKey<A> =
        HmacKey(
            BCryptStrongRandom.randomBytes(algorithm.recommendedKeySize),
            algorithm
        )

    override suspend fun exportKey(key: HmacKey<*>): ByteArray =
        key.rawKey.copyOf()

    override suspend fun <A : HmacAlgorithm> loadKey(algorithm: A, bytes: ByteArray): HmacKey<A> {
        require(bytes.size == algorithm.recommendedKeySize) {
            "Key for algotithm $algorithm should have size ${algorithm.recommendedKeySize} but was ${bytes.size}"
        }
        return HmacKey(
            bytes.copyOf(),
            algorithm
        )
    }

    private fun <T> withAlgorithmHandle(
        hmacAlgorithm: HmacAlgorithm,
        block: (BCRYPT_ALG_HANDLE) -> T
    ): T = when (hmacAlgorithm) {
        HmacAlgorithm.HmacSha512 -> withAlgorithmHandle(
            BCryptAlgorithm.BCRYPT_SHA512_ALGORITHM,
            flag = BCRYPT_ALG_HANDLE_HMAC_FLAG,
            block = block
        )
    }

    override suspend fun sign(data: ByteArray, key: HmacKey<*>): ByteArray = withAlgorithmHandle(key.algorithm) { algorithmHandle ->
        memScoped {
            val hashingBufferSize = algorithmHandle.getBCryptProperty(BCryptProperty.ObjectLengthProperty)
            val hashHandle = alloc<BCRYPT_HASH_HANDLEVar>()
            val hashingBuffer = ByteArray(hashingBufferSize)
            val pinnedHashingBuffer = hashingBuffer.pin()
            val pinnedKey = key.rawKey.pin()
            try {
                BCryptCreateHash(
                    algorithmHandle,
                    hashHandle.ptr,
                    pinnedHashingBuffer.addressOf(0).reinterpret(),
                    hashingBuffer.size.toUInt(),
                    pinnedKey.addressOf(0).reinterpret(),
                    key.rawKey.size.toUInt(),
                    0.toUInt()
                ).ensureSuccess("BCryptCreateHash")
                val hashHandleValue = hashHandle.value ?: throw PlatformMethodException(
                    "BCryptCreateHash succeeded but hash handle is null",
                    null
                )
                val pinnedData = data.pin()
                try {
                    BCryptHashData(
                        hashHandleValue,
                        pinnedData.addressOf(0).reinterpret(),
                        data.size.toUInt(),
                        0.toUInt()
                    ).ensureSuccess("BCryptHashData")
                    ByteArray(key.algorithm.digestSize).also { result ->
                        result.usePinned { pinnedResult ->
                            BCryptFinishHash(
                                hashHandleValue,
                                pinnedResult.addressOf(0).reinterpret(),
                                result.size.toUInt(),
                                0.toUInt()
                            ).ensureSuccess("BCryptFinishHash")
                        }
                    }
                } finally {
                    BCryptDestroyHash(hashHandleValue)
                    pinnedData.unpin()
                }
            } finally {
                pinnedHashingBuffer.unpin()
                pinnedKey.unpin()
            }
        }
    }

    override suspend fun verify(signature: ByteArray, data: ByteArray, key: HmacKey<*>): Boolean {
        val currentSignature = sign(data, key)
        return signature.contentEquals(currentSignature)
    }
}