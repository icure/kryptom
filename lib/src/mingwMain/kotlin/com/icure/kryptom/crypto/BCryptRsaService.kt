package com.icure.kryptom.crypto

import com.icure.kryptom.crypto.asn.AsnToJwkConverter
import com.icure.kryptom.crypto.asn.pkcs8PrivateToSpkiPublic
import com.icure.kryptom.crypto.asn.toAsn1
import com.icure.kryptom.utils.PlatformMethodException
import com.icure.kryptom.utils.ensureSuccess
import kotlinx.cinterop.CValuesRef
import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.MemScope
import kotlinx.cinterop.UIntVar
import kotlinx.cinterop.addressOf
import kotlinx.cinterop.alloc
import kotlinx.cinterop.memScoped
import kotlinx.cinterop.pin
import kotlinx.cinterop.ptr
import kotlinx.cinterop.reinterpret
import kotlinx.cinterop.usePinned
import kotlinx.cinterop.value
import kotlinx.cinterop.wcstr
import platform.windows.BCRYPT_ALG_HANDLE
import platform.windows.BCRYPT_KEY_HANDLE
import platform.windows.BCRYPT_KEY_HANDLEVar
import platform.windows.BCRYPT_OAEP_PADDING_INFO
import platform.windows.BCRYPT_PSS_PADDING_INFO
import platform.windows.BCryptDecrypt
import platform.windows.BCryptDestroyKey
import platform.windows.BCryptEncrypt
import platform.windows.BCryptExportKey
import platform.windows.BCryptFinalizeKeyPair
import platform.windows.BCryptGenerateKeyPair
import platform.windows.BCryptImportKeyPair
import platform.windows.BCryptSignHash
import platform.windows.BCryptVerifySignature

@OptIn(ExperimentalForeignApi::class)
object BCryptRsaService : RsaService {
    private const val BCRYPT_PUBLIC_KEY_BLOB = "RSAPUBLICBLOB"
    private const val BCRYPT_PRIVATE_KEY_BLOB = "RSAPRIVATEBLOB"
    private const val BCRYPT_RSAFULLPRIVATE_BLOB = "RSAFULLPRIVATEBLOB"
    private const val BCRYPT_SHA256_ALGORITHM = "SHA256"
    private const val BCRYPT_SHA1_ALGORITHM = "SHA1"
    private val BCRYPT_PAD_OAEP = 0x04.toUInt()
    private val BCRYPT_PAD_PSS = 0x08.toUInt()


    private fun <T> withAlgorithmHandle(
        algorithm: RsaAlgorithm,
        block: (algorithmHandle: BCRYPT_ALG_HANDLE) -> T
    ) = when (algorithm) {
        RsaAlgorithm.RsaEncryptionAlgorithm.OaepWithSha1 -> withAlgorithmHandle(
            BCryptAlgorithm.BCRYPT_RSA_ALGORITHM,
            block = block
        )
        RsaAlgorithm.RsaEncryptionAlgorithm.OaepWithSha256 -> withAlgorithmHandle(
            BCryptAlgorithm.BCRYPT_RSA_ALGORITHM,
            block = block
        )
        RsaAlgorithm.RsaSignatureAlgorithm.PssWithSha256 -> withAlgorithmHandle(
            BCryptAlgorithm.BCRYPT_RSA_ALGORITHM,
            block = block
        )
    }


    private fun MemScope.getPaddingInfo(
        algorithm: RsaAlgorithm.RsaEncryptionAlgorithm
    ): Pair<CValuesRef<*>, UInt> {
        val struct = alloc<BCRYPT_OAEP_PADDING_INFO>()
        struct.pszAlgId = when (algorithm) {
            RsaAlgorithm.RsaEncryptionAlgorithm.OaepWithSha1 -> BCRYPT_SHA1_ALGORITHM.wcstr.getPointer(this)
            RsaAlgorithm.RsaEncryptionAlgorithm.OaepWithSha256 -> BCRYPT_SHA256_ALGORITHM.wcstr.getPointer(this)
        }
        struct.pbLabel = null
        struct.cbLabel = 0.toUInt()
        return Pair(struct.ptr, BCRYPT_PAD_OAEP)
    }

    private fun MemScope.getPaddingInfo(
        algorithm: RsaAlgorithm.RsaSignatureAlgorithm,
    ): Pair<CValuesRef<*>, UInt> {
        val struct = alloc<BCRYPT_PSS_PADDING_INFO>()
        struct.pszAlgId = when (algorithm) {
            RsaAlgorithm.RsaSignatureAlgorithm.PssWithSha256 -> BCRYPT_SHA256_ALGORITHM.wcstr.getPointer(this)
        }
        struct.cbSalt = when (algorithm) { // Should be same as hashing algorithm
            RsaAlgorithm.RsaSignatureAlgorithm.PssWithSha256 -> 32.toUInt()
        }
        return Pair(struct.ptr, BCRYPT_PAD_PSS)
    }

    private fun <T> withRawKeyHandle(
        rawkey: ByteArray,
        blobIdentifier: String,
        algorithmHandle: BCRYPT_ALG_HANDLE,
        block: (keyHandle: BCRYPT_KEY_HANDLE) -> T
    ): T =
        memScoped {
            val keyHandle = alloc<BCRYPT_KEY_HANDLEVar>()
            rawkey.usePinned { pinnedKey ->
                BCryptImportKeyPair(
                    algorithmHandle,
                    null,
                    blobIdentifier,
                    keyHandle.ptr,
                    pinnedKey.addressOf(0).reinterpret(),
                    rawkey.size.toUInt(),
                    0.toUInt()
                ).ensureSuccess("BCryptImportKeyPair $blobIdentifier")
            }
            val keyHandleValue = keyHandle.value ?: throw PlatformMethodException(
                "BCryptImportKeyPair success but key handle is null",
                null
            )
            try {
                block(keyHandleValue)
            } finally {
                BCryptDestroyKey(keyHandleValue)
            }
        }

    private fun <T> withKeyHandle(
        key: PrivateRsaKey<*>,
        algorithmHandle: BCRYPT_ALG_HANDLE,
        block: (keyHandle: BCRYPT_KEY_HANDLE) -> T
    ): T =
        memScoped {
            val keyHandle = alloc<BCRYPT_KEY_HANDLEVar>()
            key.keyData.minimalPackedBytes.usePinned { pinnedKeyBlob ->
                BCryptImportKeyPair(
                    algorithmHandle,
                    null,
                    BCRYPT_PRIVATE_KEY_BLOB,
                    keyHandle.ptr,
                    pinnedKeyBlob.addressOf(0).reinterpret(),
                    pinnedKeyBlob.get().size.toUInt(),
                    0.toUInt()
                ).ensureSuccess("BCryptImportKeyPair private")
            }
            val keyHandleValue = keyHandle.value ?: throw PlatformMethodException(
                "BCryptImportKeyPair success but key handle is null",
                null
            )
            try {
                block(keyHandleValue)
            } finally {
                BCryptDestroyKey(keyHandleValue)
            }
        }

    private fun <T> withKeyHandle(
        key: PublicRsaKey<*>,
        algorithmHandle: BCRYPT_ALG_HANDLE,
        block: (keyHandle: BCRYPT_KEY_HANDLE) -> T
    ): T =
        memScoped {
            val keyHandle = alloc<BCRYPT_KEY_HANDLEVar>()
            key.keyData.packedBytes.usePinned { pinnedKeyBlob ->
                BCryptImportKeyPair(
                    algorithmHandle,
                    null,
                    BCRYPT_PUBLIC_KEY_BLOB,
                    keyHandle.ptr,
                    pinnedKeyBlob.addressOf(0).reinterpret(),
                    pinnedKeyBlob.get().size.toUInt(),
                    0.toUInt()
                ).ensureSuccess("BCryptImportKeyPair public")
            }
            val keyHandleValue = keyHandle.value ?: throw PlatformMethodException(
                "BCryptImportKeyPair success but key handle is null",
                null
            )
            try {
                block(keyHandleValue)
            } finally {
                BCryptDestroyKey(keyHandleValue)
            }
        }

    override suspend fun <A : RsaAlgorithm> generateKeyPair(
        algorithm: A,
        keySize: RsaService.KeySize
    ): RsaKeypair<A> = withAlgorithmHandle(algorithm) { algorithmHandle ->
        memScoped {
            val keyHandle = alloc<BCRYPT_KEY_HANDLEVar>()
            try {
                BCryptGenerateKeyPair(
                    algorithmHandle,
                    keyHandle.ptr,
                    keySize.bitSize.toUInt(),
                    0.toUInt()
                ).ensureSuccess("BCryptGenerateKeyPair")
                BCryptFinalizeKeyPair(keyHandle.value, 0.toUInt()).ensureSuccess("BCryptFinalizeKeyPair")
                val keyBlobSize = alloc<UIntVar>()
                BCryptExportKey(
                    keyHandle.value,
                    null,
                    BCRYPT_RSAFULLPRIVATE_BLOB,
                    null,
                    0.toUInt(),
                    keyBlobSize.ptr,
                    0.toUInt(),
                ).ensureSuccess("BCryptExportKey get buffer size")
                val exportedKey = ByteArray(keyBlobSize.value.toInt()).also { exportedKey ->
                    exportedKey.usePinned { exportedKeyPinned ->
                        BCryptExportKey(
                            keyHandle.value,
                            null,
                            BCRYPT_RSAFULLPRIVATE_BLOB,
                            exportedKeyPinned.addressOf(0).reinterpret(),
                            exportedKey.size.toUInt(),
                            keyBlobSize.ptr,
                            0.toUInt(),
                        ).ensureSuccess("BCryptExportKey do export")
                    }
                }.sliceArray(0 until keyBlobSize.value.toInt())
                val keyInfo = BCryptRsaFullPrivateKeyBlob.fromBytes(exportedKey)
                RsaKeypair(
                    PrivateRsaKey(
                        keyInfo,
                        algorithm
                    ),
                    PublicRsaKey(
                        keyInfo.toPublic(),
                        algorithm
                    )
                )
            } finally {
                keyHandle.value?.also {
                    BCryptDestroyKey(it)
                }
            }
        }
    }

    override suspend fun exportPrivateKeyPkcs8(key: PrivateRsaKey<*>): ByteArray =
        key.keyData.toPkcs8()

    override suspend fun exportPublicKeySpki(key: PublicRsaKey<*>): ByteArray =
        key.keyData.toSpki()

    override suspend fun <A : RsaAlgorithm> loadKeyPairPkcs8(algorithm: A, privateKeyPkcs8: ByteArray): RsaKeypair<A> =
        RsaKeypair(
            loadPrivateKeyPkcs8(algorithm, privateKeyPkcs8),
            loadPublicKeySpki(algorithm, privateKeyPkcs8.toAsn1().pkcs8PrivateToSpkiPublic().pack())
        )

    override suspend fun <A : RsaAlgorithm> loadPrivateKeyPkcs8(
        algorithm: A,
        privateKeyPkcs8: ByteArray
    ): PrivateRsaKey<A> =
        PrivateRsaKey(
            BCryptRsaFullPrivateKeyBlob.fromJwk(AsnToJwkConverter.pkcs8ToJwk(algorithm, privateKeyPkcs8)),
            algorithm,
        ).also {
            withAlgorithmHandle(algorithm) { algorithmHandle -> withKeyHandle(it, algorithmHandle) {
                // Do nothing, just verify it can be imported
            } }
        }

    override suspend fun <A : RsaAlgorithm> loadPublicKeySpki(algorithm: A, publicKeySpki: ByteArray): PublicRsaKey<A> =
        PublicRsaKey(
            BCryptRsaPublicKeyBlob.fromJwk(AsnToJwkConverter.spkiToJwk(algorithm, publicKeySpki)),
            algorithm,
        ).also {
            withAlgorithmHandle(algorithm) { algorithmHandle -> withKeyHandle(it, algorithmHandle) {
                // Do nothing, just verify it can be imported
            } }
        }

    override suspend fun encrypt(
        data: ByteArray,
        publicKey: PublicRsaKey<RsaAlgorithm.RsaEncryptionAlgorithm>
    ): ByteArray = withAlgorithmHandle(publicKey.algorithm) { algorithmHandle ->
        withKeyHandle(publicKey, algorithmHandle) { keyHandle ->
            memScoped {
                val (paddingInfo, paddingOption) = getPaddingInfo(publicKey.algorithm)
                val resultBufferSize = alloc<UIntVar>()
                data.usePinned { pinnedData ->
                    BCryptEncrypt(
                        keyHandle,
                        pinnedData.addressOf(0).reinterpret(),
                        data.size.toUInt(),
                        paddingInfo,
                        null,
                        0.toUInt(),
                        null,
                        0.toUInt(),
                        resultBufferSize.ptr,
                        paddingOption,
                    ).ensureSuccess("BCryptEncrypt get buffer size")
                    ByteArray(resultBufferSize.value.toInt()).also { result ->
                        result.usePinned { pinnedResult ->
                            BCryptEncrypt(
                                keyHandle,
                                pinnedData.addressOf(0).reinterpret(),
                                data.size.toUInt(),
                                paddingInfo,
                                null,
                                0.toUInt(),
                                pinnedResult.addressOf(0).reinterpret(),
                                result.size.toUInt(),
                                resultBufferSize.ptr,
                                paddingOption,
                            ).ensureSuccess("BCryptEncrypt do encrypt")
                            if (result.size != resultBufferSize.value.toInt()) throw PlatformMethodException(
                                "Size of output changed between get size and do encrypt",
                                null
                            )
                        }
                    }
                }
            }
        }
    }

    override suspend fun decrypt(
        data: ByteArray,
        privateKey: PrivateRsaKey<RsaAlgorithm.RsaEncryptionAlgorithm>
    ): ByteArray = withAlgorithmHandle(privateKey.algorithm) { algorithmHandle ->
        withKeyHandle(privateKey, algorithmHandle) { keyHandle ->
            memScoped {
                val (paddingInfo, paddingOption) = getPaddingInfo(privateKey.algorithm)
                val resultBufferSize = alloc<UIntVar>()
                data.usePinned { pinnedData ->
                    BCryptDecrypt(
                        keyHandle,
                        pinnedData.addressOf(0).reinterpret(),
                        data.size.toUInt(),
                        paddingInfo,
                        null,
                        0.toUInt(),
                        null,
                        0.toUInt(),
                        resultBufferSize.ptr,
                        paddingOption,
                    ).ensureSuccess("BCryptDecrypt get buffer size")
                    ByteArray(resultBufferSize.value.toInt()).also { result ->
                        result.usePinned { pinnedResult ->
                            BCryptDecrypt(
                                keyHandle,
                                pinnedData.addressOf(0).reinterpret(),
                                data.size.toUInt(),
                                paddingInfo,
                                null,
                                0.toUInt(),
                                pinnedResult.addressOf(0).reinterpret(),
                                result.size.toUInt(),
                                resultBufferSize.ptr,
                                paddingOption,
                            ).ensureSuccess("BCryptDecrypt do decrypt")
                            if (result.size != resultBufferSize.value.toInt()) throw PlatformMethodException(
                                "Size of output changed between get size and do decrypt",
                                null
                            )
                        }
                    }
                }
            }
        }
    }

    private fun hashDataForAlgorithm(
        algorithm: RsaAlgorithm.RsaSignatureAlgorithm,
        data: ByteArray,
    ): ByteArray = when (algorithm) {
        RsaAlgorithm.RsaSignatureAlgorithm.PssWithSha256 -> BCryptDigest.sha256(data)
    }

    override suspend fun sign(
        data: ByteArray,
        privateKey: PrivateRsaKey<RsaAlgorithm.RsaSignatureAlgorithm>
    ): ByteArray = withAlgorithmHandle(privateKey.algorithm) { algorithmHandle ->
        withKeyHandle(privateKey, algorithmHandle) { keyHandle ->
            hashDataForAlgorithm(privateKey.algorithm, data).usePinned { pinnedDataHash ->
                memScoped {
                    val (paddingInfo, paddingOption) = getPaddingInfo(privateKey.algorithm)
                    val signatureSize = alloc<UIntVar>()
                    BCryptSignHash(
                        keyHandle,
                        paddingInfo,
                        pinnedDataHash.addressOf(0).reinterpret(),
                        pinnedDataHash.get().size.toUInt(),
                        null,
                        0.toUInt(),
                        signatureSize.ptr,
                        paddingOption
                    ).ensureSuccess("BCryptSignHash get signature size")
                    val result = ByteArray(signatureSize.value.toInt())
                    result.usePinned { pinnedResult ->
                        BCryptSignHash(
                            keyHandle,
                            paddingInfo,
                            pinnedDataHash.addressOf(0).reinterpret(),
                            pinnedDataHash.get().size.toUInt(),
                            pinnedResult.addressOf(0).reinterpret(),
                            result.size.toUInt(),
                            signatureSize.ptr,
                            paddingOption
                        ).ensureSuccess("BCryptSignHash do sign")
                    }
                    if (result.size != signatureSize.value.toInt()) throw PlatformMethodException(
                        "Size of signature changed between get size and do sign",
                        null
                    )
                    result
                }
            }
        }
    }

    override suspend fun verifySignature(
        signature: ByteArray,
        data: ByteArray,
        publicKey: PublicRsaKey<RsaAlgorithm.RsaSignatureAlgorithm>
    ): Boolean = withAlgorithmHandle(publicKey.algorithm) { algorithmHandle ->
        withKeyHandle(publicKey, algorithmHandle) { keyHandle ->
            val pinnedDataHash = hashDataForAlgorithm(publicKey.algorithm, data).pin()
            val pinnedSignature = signature.pin()
            try {
                memScoped {
                    val (paddingInfo, paddingOption) = getPaddingInfo(publicKey.algorithm)
                    val verifyResult = BCryptVerifySignature(
                        keyHandle,
                        paddingInfo,
                        pinnedDataHash.addressOf(0).reinterpret(),
                        pinnedDataHash.get().size.toUInt(),
                        pinnedSignature.addressOf(0).reinterpret(),
                        pinnedSignature.get().size.toUInt(),
                        paddingOption
                    )
                    // Only -1073700864 / 0xC000A000 is supposed to be the status for unverified signature, but I'm
                    // consistently getting C000000D instead...
                    verifyResult == 0
                }
            } finally {
                pinnedDataHash.unpin()
                pinnedSignature.unpin()
            }
        }
    }
}