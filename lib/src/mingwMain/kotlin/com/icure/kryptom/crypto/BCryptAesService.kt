package com.icure.kryptom.crypto

import com.icure.kryptom.utils.PlatformMethodException
import com.icure.kryptom.utils.ensureSuccess
import com.icure.kryptom.utils.toHexString
import kotlinx.cinterop.*
import platform.posix.memcpy
import platform.windows.*

@OptIn(ExperimentalForeignApi::class)
object BCryptAesService : AesService {
    fun <T> withAlgorithmHandle(
        algorithm: AesAlgorithm,
        block: (BCRYPT_ALG_HANDLE) -> T
    ): T = when (algorithm) {
        AesAlgorithm.CbcWithPkcs7Padding -> withAlgorithmHandle(
            BCryptAlgorithm.BCRYPT_AES_ALGORITHM,
            BCryptProperty.BlockChainingMode.BCRYPT_CHAIN_MODE_CBC,
            block = block
        )
    }

    // TODO use actual key generation solution
    override suspend fun <A : AesAlgorithm> generateKey(algorithm: A, size: AesService.KeySize): AesKey<A> =
        AesKey(
            BCryptStrongRandom.randomBytes(size.byteSize),
            algorithm
        )

    override suspend fun exportKey(key: AesKey<*>): ByteArray =
        key.rawKey.copyOf()

    override suspend fun <A : AesAlgorithm> loadKey(algorithm: A, bytes: ByteArray): AesKey<A> =
        AesKey(
            bytes.copyOf(),
            algorithm
        )

    private fun <T> withKeyHandle(
        key: AesKey<*>,
        algorithmHandle: BCRYPT_ALG_HANDLE,
        block: (BCRYPT_KEY_HANDLE) -> T
    ): T = memScoped {
        val keyDataHeaderStruct = alloc<BCRYPT_KEY_DATA_BLOB_HEADER>()
        keyDataHeaderStruct.dwMagic = BCRYPT_KEY_DATA_BLOB_MAGIC.toUInt()
        keyDataHeaderStruct.dwVersion = 1.toUInt()
        keyDataHeaderStruct.cbKeyData = key.rawKey.size.toUInt()
        val keyBlob = ByteArray(sizeOf<BCRYPT_KEY_DATA_BLOB_HEADER>().toInt() + key.rawKey.size)
        keyBlob.usePinned { blob ->
            memcpy(blob.addressOf(0), keyDataHeaderStruct.ptr, sizeOf<BCRYPT_KEY_DATA_BLOB_HEADER>().toULong())
            key.rawKey.usePinned { pinnedKey ->
                memcpy(blob.addressOf(sizeOf<BCRYPT_KEY_DATA_BLOB_HEADER>().toInt()), pinnedKey.addressOf(0), key.rawKey.size.toULong())
            }
            val keyHandle = alloc<BCRYPT_KEY_HANDLEVar>()
            BCryptImportKey(
                algorithmHandle,
                null,
                "KeyDataBlob", // #define BCRYPT_KEY_DATA_BLOB L"KeyDataBlob" https://github.com/tpn/winsdk-10/blob/9b69fd26ac0c7d0b83d378dba01080e93349c2ed/Include/10.0.14393.0/shared/bcrypt.h#L255C39-L255C50
                keyHandle.ptr,
                null,
                0.toUInt(),
                blob.addressOf(0).reinterpret(),
                keyBlob.size.toUInt(),
                0.toUInt()
            ).ensureSuccess("BCryptImportKey")
            val handleValue = keyHandle.value
                ?: throw PlatformMethodException("BCryptImportKey was successful but handle is null", null)
            try {
                block(handleValue)
            } finally {
                BCryptDestroyKey(handleValue)
            }
        }
    }

    override suspend fun encrypt(
        data: ByteArray,
        key: AesKey<*>,
        iv: ByteArray?
    ): ByteArray = withAlgorithmHandle(key.algorithm) { algorithmHandle ->
        withKeyHandle(key, algorithmHandle) { keyHandle ->
            val generatedIv = iv ?: BCryptStrongRandom.randomBytes(AesService.IV_BYTE_LENGTH)
            val ivCopy = generatedIv.copyOf()
            val pinnedIv = ivCopy.pin()
            val pinnedData = data.pin()
            try {
                memScoped {
                    val cyphertextSize = alloc<UIntVar>()
                    BCryptEncrypt(
                        keyHandle,
                        pinnedData.addressOf(0).reinterpret(),
                        data.size.toUInt(),
                        null,
                        pinnedIv.addressOf(0).reinterpret(),
                        ivCopy.size.toUInt(),
                        null,
                        0.toUInt(),
                        cyphertextSize.ptr,
                        1.toUInt() // BCRYPT_BLOCK_PADDING
                    ).ensureSuccess("BCryptEncrypt get cyphertext size")
                    val dataLen = alloc<UIntVar>()
                    val encrypted = ByteArray(cyphertextSize.value.toInt())
                    encrypted.usePinned { pinnedEncrypted ->
                        BCryptEncrypt(
                            keyHandle,
                            pinnedData.addressOf(0).reinterpret(),
                            data.size.toUInt(),
                            null,
                            pinnedIv.addressOf(0).reinterpret(),
                            ivCopy.size.toUInt(),
                            pinnedEncrypted.addressOf(0).reinterpret(),
                            (encrypted.size).toUInt(),
                            dataLen.ptr,
                            1.toUInt() // BCRYPT_BLOCK_PADDING
                        ).ensureSuccess("BCryptEncrypt do encrypt")
                    }
                    check(dataLen.value == cyphertextSize.value) {
                        "Data from do encrypt has different size from get size"
                    }
                    generatedIv + encrypted
                }
            } finally {
                pinnedIv.unpin()
                pinnedData.unpin()
            }
        }
    }

    override suspend fun decrypt(ivAndEncryptedData: ByteArray, key: AesKey<*>): ByteArray = withAlgorithmHandle(key.algorithm) { algorithmHandle ->
        withKeyHandle(key, algorithmHandle) { keyHandle ->
            val iv = ivAndEncryptedData.sliceArray(0 until AesService.IV_BYTE_LENGTH)
            val pinnedIv = iv.pin()
            val data = ivAndEncryptedData.sliceArray(AesService.IV_BYTE_LENGTH until ivAndEncryptedData.size)
            val pinnedData = data.pin()
            try {
                memScoped {
                    val decryptedTextBufferSize = alloc<UIntVar>()
                    BCryptDecrypt(
                        keyHandle,
                        pinnedData.addressOf(0).reinterpret(),
                        data.size.toUInt(),
                        null,
                        pinnedIv.addressOf(0).reinterpret(),
                        iv.size.toUInt(),
                        null,
                        0.toUInt(),
                        decryptedTextBufferSize.ptr,
                        1.toUInt() // BCRYPT_BLOCK_PADDING
                    ).ensureSuccess("BCryptDecrypt get decrypted size")
                    val actualDecryptedSize = alloc<UIntVar>()
                    val decryptedData = ByteArray(decryptedTextBufferSize.value.toInt())
                    decryptedData.usePinned { pinnedDecrypted ->
                        BCryptDecrypt(
                            keyHandle,
                            pinnedData.addressOf(0).reinterpret(),
                            data.size.toUInt(),
                            null,
                            pinnedIv.addressOf(0).reinterpret(),
                            iv.size.toUInt(),
                            pinnedDecrypted.addressOf(0).reinterpret(),
                            decryptedData.size.toUInt(),
                            actualDecryptedSize.ptr,
                            1.toUInt() // BCRYPT_BLOCK_PADDING
                        ).ensureSuccess("BCryptDecrypt do decrypt")
                    }
                    decryptedData.sliceArray(0 until actualDecryptedSize.value.toInt())
                }
            } finally {
                pinnedIv.unpin()
                pinnedData.unpin()
            }
        }
    }
}