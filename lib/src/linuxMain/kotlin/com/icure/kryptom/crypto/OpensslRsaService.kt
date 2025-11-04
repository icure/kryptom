package com.icure.kryptom.crypto

import com.icure.kryptom.crypto.asn.pkcs8PrivateToSpkiPublic
import com.icure.kryptom.crypto.asn.toAsn1
import com.icure.kryptom.utils.OpensslErrorHandling
import com.icure.kryptom.utils.OpensslErrorHandling.ensureEvpSuccess
import com.icure.kryptom.utils.PlatformMethodException
import com.icure.kryptom.utils.base64Decode
import com.icure.kryptom.utils.base64Encode
import com.icure.kryptom.utils.readingFromBio
import com.icure.kryptom.utils.writingToBio
import kotlinx.cinterop.CPointer
import kotlinx.cinterop.CPointerVar
import kotlinx.cinterop.CValuesRef
import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.ULongVar
import kotlinx.cinterop.addressOf
import kotlinx.cinterop.alloc
import kotlinx.cinterop.memScoped
import kotlinx.cinterop.pin
import kotlinx.cinterop.ptr
import kotlinx.cinterop.usePinned
import kotlinx.cinterop.value
import libcrypto.BN_new
import libcrypto.BN_set_word
import libcrypto.ERR_clear_error
import libcrypto.EVP_DigestSignFinal
import libcrypto.EVP_DigestSignInit
import libcrypto.EVP_DigestSignUpdate
import libcrypto.EVP_DigestVerifyFinal
import libcrypto.EVP_DigestVerifyInit
import libcrypto.EVP_DigestVerifyUpdate
import libcrypto.EVP_MD_CTX
import libcrypto.EVP_MD_CTX_free
import libcrypto.EVP_MD_CTX_get_pkey_ctx
import libcrypto.EVP_MD_CTX_new
import libcrypto.EVP_PKEY
import libcrypto.EVP_PKEY_CTX
import libcrypto.EVP_PKEY_CTX_free
import libcrypto.EVP_PKEY_CTX_new
import libcrypto.EVP_PKEY_CTX_new_id
import libcrypto.EVP_PKEY_CTX_set_rsa_keygen_bits
import libcrypto.EVP_PKEY_CTX_set_rsa_keygen_pubexp
import libcrypto.EVP_PKEY_CTX_set_rsa_oaep_md
import libcrypto.EVP_PKEY_CTX_set_rsa_padding
import libcrypto.EVP_PKEY_RSA
import libcrypto.EVP_PKEY_decrypt
import libcrypto.EVP_PKEY_decrypt_init
import libcrypto.EVP_PKEY_encrypt
import libcrypto.EVP_PKEY_encrypt_init
import libcrypto.EVP_PKEY_free
import libcrypto.EVP_PKEY_generate
import libcrypto.EVP_PKEY_keygen_init
import libcrypto.EVP_sha1
import libcrypto.EVP_sha256
import libcrypto.PEM_read_bio_PUBKEY
import libcrypto.PEM_read_bio_PrivateKey
import libcrypto.PEM_write_bio_PKCS8PrivateKey
import libcrypto.PEM_write_bio_PUBKEY
import libcrypto.RSA_F4
import libcrypto.RSA_PKCS1_OAEP_PADDING
import libcrypto.RSA_PKCS1_PSS_PADDING

@OptIn(ExperimentalForeignApi::class)
/*
 * Note: in this implementation there are various cases where the usual way of implementing the operation in c can't be
 * used in kotlin because they are defined as macro. Examples:
 * - EVP_RSA_gen uses EVP_PKEY_Q_keygen
 * - BIO_get_mem_data uses BIO_ctrl
 */
object OpensslRsaService : RsaService {
    private const val PEM_PRIVATE_HEADER = "-----BEGIN PRIVATE KEY-----\n"
    private const val PEM_PRIVATE_FOOTER = "-----END PRIVATE KEY-----\n"
    private const val PEM_PUBLIC_HEADER = "-----BEGIN PUBLIC KEY-----\n"
    private const val PEM_PUBLIC_FOOTER = "-----END PUBLIC KEY-----\n"

    override suspend fun <A : RsaAlgorithm> generateKeyPair(algorithm: A, keySize: RsaService.KeySize): RsaKeypair<A> =
        memScoped {
            val ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, null) ?: throw PlatformMethodException("Could not initialise context", null)
            val e = BN_new()
            val keyPtr = alloc<CPointerVar<EVP_PKEY>>()
            try {
                EVP_PKEY_keygen_init(ctx).ensureEvpSuccess("EVP_PKEY_keygen_init")
                EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, keySize.bitSize).ensureEvpSuccess("EVP_PKEY_CTX_set_rsa_keygen_bits")
                BN_set_word(e, RSA_F4.toULong()).ensureEvpSuccess("BN_set_word") // 65537
                EVP_PKEY_CTX_set_rsa_keygen_pubexp(ctx, e).ensureEvpSuccess("EVP_PKEY_CTX_set_rsa_keygen_pubexp")
                EVP_PKEY_generate(ctx, keyPtr.ptr).ensureEvpSuccess("EVP_PKEY_generate")
                RsaKeypair(
                    PrivateRsaKey(
                        getPemPkcs8Bytes(keyPtr).decodeToString(),
                        algorithm
                    ),
                    PublicRsaKey(
                        getPemSpkiBytes(keyPtr).decodeToString(),
                        algorithm
                    )
                )
            } finally {
                EVP_PKEY_CTX_free(ctx) // Also frees up e (no need to do BN_free(e))
                if (keyPtr.value != null) EVP_PKEY_free(keyPtr.value)
            }
        }

    private fun getPemPkcs8Bytes(
        key: CPointerVar<EVP_PKEY>
    ): ByteArray = writingToBio(true) {
        PEM_write_bio_PKCS8PrivateKey(
            it,
            key.value,
            null,
            null,
            0,
            null,
            null
        ).ensureEvpSuccess("PEM_write_bio_PKCS8PrivateKey")
    }

    private fun getPemSpkiBytes(
        key: CPointerVar<EVP_PKEY>
    ): ByteArray = writingToBio(true) {
        PEM_write_bio_PUBKEY(it, key.value)
    }

    override suspend fun exportPrivateKeyPkcs8(key: PrivateRsaKey<*>): ByteArray {
        require(key.pemPkcs8Key.startsWith(PEM_PRIVATE_HEADER)) { "Key does not start with private key header" }
        require(key.pemPkcs8Key.endsWith(PEM_PRIVATE_FOOTER)) { "Key does not end with private key footer" }
        return base64Decode(key.pemPkcs8Key
            .removePrefix(PEM_PRIVATE_HEADER)
            .removeSuffix(PEM_PRIVATE_FOOTER)
            .filter { it != '\n' }
        )
    }

    override suspend fun exportPublicKeySpki(key: PublicRsaKey<*>): ByteArray  {
        require(key.pemSpkiKey.startsWith(PEM_PUBLIC_HEADER)) { "Key does not start with public key header" }
        require(key.pemSpkiKey.endsWith(PEM_PUBLIC_FOOTER)) { "Key does not end with public key footer" }
        return base64Decode(key.pemSpkiKey
            .removePrefix(PEM_PUBLIC_HEADER)
            .removeSuffix(PEM_PUBLIC_FOOTER)
            .filter { it != '\n' }
        )
    }

    override suspend fun <A : RsaAlgorithm> loadKeyPairPkcs8(algorithm: A, privateKeyPkcs8: ByteArray): RsaKeypair<A> =
        RsaKeypair(
            loadPrivateKeyPkcs8(algorithm, privateKeyPkcs8),
            loadPublicKeySpki(algorithm, privateKeyPkcs8.toAsn1().pkcs8PrivateToSpkiPublic().pack())
        )

    private fun ByteArray.toPemString(header: String, footer: String) = buildString {
        append(header)
        base64Encode(this@toPemString).chunked(64).forEach {
            append(it)
            append("\n")
        }
        append(footer)
    }

    override suspend fun <A : RsaAlgorithm> loadPrivateKeyPkcs8(
        algorithm: A,
        privateKeyPkcs8: ByteArray
    ): PrivateRsaKey<A> =
        PrivateRsaKey(
            privateKeyPkcs8.toPemString(PEM_PRIVATE_HEADER, PEM_PRIVATE_FOOTER),
            algorithm
        ).also { it.use { /* do nothing, just force an import to make sure the key is valid */ } }

    override suspend fun <A : RsaAlgorithm> loadPublicKeySpki(algorithm: A, publicKeySpki: ByteArray): PublicRsaKey<A> =
        PublicRsaKey(
            publicKeySpki.toPemString(PEM_PUBLIC_HEADER, PEM_PUBLIC_FOOTER),
            algorithm
        ).also { it.use { /* do nothing, just force an import to make sure the key is valid */ } }

    private fun <T> PublicRsaKey<*>.use(
        block: (CPointer<EVP_PKEY>) -> T
    ): T {
        val key = readingFromBio(pemSpkiKey.encodeToByteArray()) {
            PEM_read_bio_PUBKEY(
                it,
                null,
                null,
                null
            ) ?: throw PlatformMethodException("Could not load public key", null)
        }
        return try {
            block(key)
        } finally {
            EVP_PKEY_free(key)
        }
    }

    private fun <T> PrivateRsaKey<*>.use(
        block: (CPointer<EVP_PKEY>) -> T
    ): T {
        val key = readingFromBio(pemPkcs8Key.encodeToByteArray()) {
            PEM_read_bio_PrivateKey(
                it,
                null,
                null,
                null
            ) ?: throw PlatformMethodException("Could not load private key", null)
        }
        return try {
            block(key)
        } finally {
            EVP_PKEY_free(key)
        }
    }

    private fun initializeEncryptionOrDecryptionContextParams(
        ctx: CValuesRef<EVP_PKEY_CTX>,
        algorithm: RsaAlgorithm.RsaEncryptionAlgorithm
    ) {
        EVP_PKEY_CTX_set_rsa_padding(
            ctx,
            RSA_PKCS1_OAEP_PADDING
        ).ensureEvpSuccess("EVP_PKEY_CTX_set_rsa_padding")
        EVP_PKEY_CTX_set_rsa_oaep_md(
            ctx,
            when (algorithm) {
                RsaAlgorithm.RsaEncryptionAlgorithm.OaepWithSha1 -> EVP_sha1()
                RsaAlgorithm.RsaEncryptionAlgorithm.OaepWithSha256 -> EVP_sha256()
            }
        ).ensureEvpSuccess("EVP_PKEY_CTX_set_rsa_oaep_md")
    }

    override suspend fun encrypt(
        data: ByteArray,
        publicKey: PublicRsaKey<RsaAlgorithm.RsaEncryptionAlgorithm>
    ): ByteArray = publicKey.use { key ->
        memScoped {
            val ctx = EVP_PKEY_CTX_new(key, null) ?: throw PlatformMethodException("Could not initialise context", null)
            val pinnedInput = data.asUByteArray().pin()
            try {
                EVP_PKEY_encrypt_init(ctx).ensureEvpSuccess("EVP_PKEY_encrypt_init")
                initializeEncryptionOrDecryptionContextParams(ctx, publicKey.algorithm)
                val outlen = alloc<ULongVar>()
                EVP_PKEY_encrypt(ctx, null, outlen.ptr, pinnedInput.addressOf(0), data.size.toULong()).ensureEvpSuccess("EVP_PKEY_encrypt-len")
                val output = UByteArray(outlen.value.toInt())
                output.usePinned {
                    EVP_PKEY_encrypt(ctx, it.addressOf(0), outlen.ptr, pinnedInput.addressOf(0), data.size.toULong()).ensureEvpSuccess("EVP_PKEY_encrypt")
                }
                check(outlen.value.toInt() == output.size) { "Output size is not the expected" }
                output.asByteArray()
            } finally {
                EVP_PKEY_CTX_free(ctx)
                pinnedInput.unpin()
            }
        }
    }

    override suspend fun decrypt(
        data: ByteArray,
        privateKey: PrivateRsaKey<RsaAlgorithm.RsaEncryptionAlgorithm>
    ): ByteArray = privateKey.use { key ->
        memScoped {
            val ctx = EVP_PKEY_CTX_new(key, null) ?: throw PlatformMethodException("Could not initialise context", null)
            val pinnedInput = data.asUByteArray().pin()
            try {
                EVP_PKEY_decrypt_init(ctx).ensureEvpSuccess("EVP_PKEY_encrypt_init")
                initializeEncryptionOrDecryptionContextParams(ctx, privateKey.algorithm)
                val outlen = alloc<ULongVar>()
                EVP_PKEY_decrypt(ctx, null, outlen.ptr, pinnedInput.addressOf(0), data.size.toULong()).ensureEvpSuccess("EVP_PKEY_decrypt-len")
                val output = UByteArray(outlen.value.toInt())
                output.usePinned {
                    EVP_PKEY_decrypt(ctx, it.addressOf(0), outlen.ptr, pinnedInput.addressOf(0), data.size.toULong()).ensureEvpSuccess("EVP_PKEY_decrypt")
                }
                output.asByteArray().sliceArray(0 until outlen.value.toInt())
            } finally {
                EVP_PKEY_CTX_free(ctx)
                pinnedInput.unpin()
            }
        }
    }

    fun RsaAlgorithm.RsaSignatureAlgorithm.EVP_digest() = when (this) {
        RsaAlgorithm.RsaSignatureAlgorithm.PssWithSha256 -> EVP_sha256()
    }

    private fun initializeSignatureOrVerificationContextParams(
        ctx: CValuesRef<EVP_MD_CTX>,
        algorithm: RsaAlgorithm.RsaSignatureAlgorithm
    ) {
        // No need to free explicitly the returned value, will be freed with ctx
        val pkeyCtx = EVP_MD_CTX_get_pkey_ctx(ctx) ?: throw PlatformMethodException("EVP_MD_CTX_get_pkey_ctx returned null", null)
        EVP_PKEY_CTX_set_rsa_padding(
            pkeyCtx,
            when (algorithm) {
                RsaAlgorithm.RsaSignatureAlgorithm.PssWithSha256 -> RSA_PKCS1_PSS_PADDING
            }
        ).ensureEvpSuccess("EVP_PKEY_CTX_set_rsa_padding")
    }

    override suspend fun sign(
        data: ByteArray,
        privateKey: PrivateRsaKey<RsaAlgorithm.RsaSignatureAlgorithm>
    ): ByteArray = privateKey.use { key ->
        memScoped {
            val ctx = EVP_MD_CTX_new() ?: throw PlatformMethodException("Could not initialise context", null)
            val pinnedData = data.asUByteArray().pin()
            try {
                EVP_DigestSignInit(
                    ctx,
                    null,
                    privateKey.algorithm.EVP_digest(),
                    null,
                    key
                ).ensureEvpSuccess("EVP_DigestSignInit")
                initializeSignatureOrVerificationContextParams(ctx, privateKey.algorithm)
                EVP_DigestSignUpdate(ctx, pinnedData.addressOf(0), data.size.toULong()).ensureEvpSuccess("EVP_DigestSignUpdate")
                val outlen = alloc<ULongVar>()
                EVP_DigestSignFinal(ctx, null, outlen.ptr).ensureEvpSuccess("EVP_DigestSignFinal-len")
                val output = ByteArray(outlen.value.toInt())
                output.asUByteArray().usePinned {
                    EVP_DigestSignFinal(ctx, it.addressOf(0), outlen.ptr).ensureEvpSuccess("EVP_DigestSignFinal")
                }
                check(outlen.value.toInt() == output.size) { "Output size is not the expected" }
                output
            } finally {
                EVP_MD_CTX_free(ctx)
                pinnedData.unpin()
            }
        }
    }

    override suspend fun verifySignature(
        signature: ByteArray,
        data: ByteArray,
        publicKey: PublicRsaKey<RsaAlgorithm.RsaSignatureAlgorithm>
    ): Boolean = publicKey.use { key ->
        memScoped {
            val ctx = EVP_MD_CTX_new() ?: throw PlatformMethodException("Could not initialise context", null)
            val pinnedData = data.asUByteArray().pin()
            val pinnedSignature = signature.asUByteArray().pin()
            try {
                EVP_DigestVerifyInit(
                    ctx,
                    null,
                    publicKey.algorithm.EVP_digest(),
                    null,
                    key
                ).ensureEvpSuccess("EVP_DigestVerifyInit")
                initializeSignatureOrVerificationContextParams(ctx, publicKey.algorithm)
                EVP_DigestVerifyUpdate(ctx, pinnedData.addressOf(0), data.size.toULong()).ensureEvpSuccess("EVP_DigestVerifyUpdate")
                when (val verifyResult = EVP_DigestVerifyFinal(ctx, pinnedSignature.addressOf(0), signature.size.toULong())) {
                    0 -> false.also { // 0 in this case does not mean an error but only means that the signature did not verify
                        ERR_clear_error() // But there will still be an error tracked
                    }
                    1 -> true
                    else -> OpensslErrorHandling.throwExceptionForCode(verifyResult)
                }
            } finally {
                EVP_MD_CTX_free(ctx)
                pinnedData.unpin()
                pinnedSignature.unpin()
            }
        }
    }
}
