package com.icure.kryptom.crypto

import com.icure.kryptom.utils.PlatformMethodException
import com.icure.kryptom.utils.ensureSuccess
import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.addressOf
import kotlinx.cinterop.alloc
import kotlinx.cinterop.memScoped
import kotlinx.cinterop.pin
import kotlinx.cinterop.ptr
import kotlinx.cinterop.reinterpret
import kotlinx.cinterop.usePinned
import kotlinx.cinterop.value
import platform.windows.BCRYPT_HASH_HANDLEVar
import platform.windows.BCryptCreateHash
import platform.windows.BCryptDestroyHash
import platform.windows.BCryptFinishHash
import platform.windows.BCryptHashData

object BCryptDigestService : DigestService {
    override suspend fun sha256(
        data: ByteArray
    ): ByteArray = BCryptDigest.sha256(data)
}

/**
 * The non-multiplatform service, same as the other but the methods are not suspend
 */
@OptIn(ExperimentalForeignApi::class)
internal object BCryptDigest {
    fun sha256(data: ByteArray): ByteArray =
        withAlgorithmHandle(BCryptAlgorithm.BCRYPT_SHA256_ALGORITHM) { algorithmHandle ->
            memScoped {
                val hashingBufferSize = algorithmHandle.getBCryptProperty(BCryptProperty.ObjectLengthProperty)
                val hashHandle = alloc<BCRYPT_HASH_HANDLEVar>()
                val hashingBuffer = ByteArray(hashingBufferSize)
                val pinnedHashingBuffer = hashingBuffer.pin()
                try {
                    BCryptCreateHash(
                        algorithmHandle,
                        hashHandle.ptr,
                        pinnedHashingBuffer.addressOf(0).reinterpret(),
                        hashingBuffer.size.toUInt(),
                        null,
                        0.toUInt(),
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
                        ByteArray(32).also { result ->
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
                }
            }
        }
}
