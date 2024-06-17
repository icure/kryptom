package com.icure.kryptom.crypto

import com.icure.kryptom.crypto.asn.pkcs8PrivateToSpkiPublic
import com.icure.kryptom.crypto.asn.toAsn1
import com.icure.kryptom.utils.OpensslErrorHandling.ensureEvpSuccess
import com.icure.kryptom.utils.PlatformMethodException
import com.icure.kryptom.utils.base64Decode
import io.ktor.util.encodeBase64
import kotlinx.cinterop.ByteVar
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
import kotlinx.cinterop.readBytes
import kotlinx.cinterop.usePinned
import kotlinx.cinterop.value
import libcrypto.BIO
import libcrypto.BIO_CTRL_INFO
import libcrypto.BIO_ctrl
import libcrypto.BIO_free_all
import libcrypto.BIO_new
import libcrypto.BIO_s_mem
import libcrypto.BIO_write_ex
import libcrypto.BN_new
import libcrypto.BN_set_word
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

    // Initializes a bio, executes a lambda that writes something to that bio, then creates a kotlin byte array with the
    // data from the bio and frees the original bio before returning.
    private fun writingToBio(
        writeToBio: (bio: CPointer<BIO>) -> Unit
    ): ByteArray = memScoped {
        val bio = BIO_new(BIO_s_mem()) ?: throw PlatformMethodException("Could not initialise bio", null)
        val bioDataStart = alloc<CPointerVar<ByteVar>>()
        try {
            writeToBio(bio)
            val length = BIO_ctrl(bio, BIO_CTRL_INFO, 0, bioDataStart.ptr).toInt()
            check(length > 0) { "BIO_CTRL_INFO returned $length" }
            checkNotNull(bioDataStart.value?.readBytes(length)) {
                "BIO data points to null"
            }
        } finally {
            BIO_free_all(bio)
        }
    }

    private fun getPemPkcs8Bytes(
        key: CPointerVar<EVP_PKEY>
    ): ByteArray = writingToBio {
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
    ): ByteArray = writingToBio {
        PEM_write_bio_PUBKEY(it, key.value)
    }

    override suspend fun exportPrivateKeyPkcs8(key: PrivateRsaKey<*>): ByteArray {
        require(key.pemPkcs8Key.startsWith(PEM_PRIVATE_HEADER)) { "Key does not start with private key header" }
        require(key.pemPkcs8Key.startsWith(PEM_PRIVATE_FOOTER)) { "Key does not start with private key footer" }
        return base64Decode(key.pemPkcs8Key
            .removePrefix(PEM_PRIVATE_HEADER)
            .removeSuffix(PEM_PRIVATE_FOOTER)
            .filter { it != '\n' }
        )
    }

    override suspend fun exportPublicKeySpki(key: PublicRsaKey<*>): ByteArray  {
        require(key.pemSpkiKey.startsWith(PEM_PUBLIC_HEADER)) { "Key does not start with public key header" }
        require(key.pemSpkiKey.startsWith(PEM_PUBLIC_FOOTER)) { "Key does not start with public key footer" }
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
        this@toPemString.encodeBase64().chunked(64).forEach {
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
        )

    override suspend fun <A : RsaAlgorithm> loadPublicKeySpki(algorithm: A, publicKeySpki: ByteArray): PublicRsaKey<A> =
        PublicRsaKey(
            publicKeySpki.toPemString(PEM_PUBLIC_HEADER, PEM_PUBLIC_FOOTER),
            algorithm
        )

    private fun <T> readingFromBio(
        data: ByteArray,
        readFromBio: (readFromBio: CPointer<BIO>) -> T
    ): T = memScoped {
        data.usePinned {
            val written = alloc<ULongVar>()
            val bio = BIO_new(BIO_s_mem()) ?: throw PlatformMethodException("Could not initialise bio", null)
            try {
                BIO_write_ex(bio, it.addressOf(0), data.size.toULong(), written.ptr).ensureEvpSuccess(
                    "BIO_write_ex"
                )
                check(written.value.toInt() == data.size) {
                    "Written bytes and data size differ (written: ${written.value}, data size: ${data.size})"
                }
                readFromBio(bio)
            } finally {
                BIO_free_all(bio)
            }
        }
    }

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

    private fun initializeEncryptionDecryptionContextParams(
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
                initializeEncryptionDecryptionContextParams(ctx, publicKey.algorithm)
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
                initializeEncryptionDecryptionContextParams(ctx, privateKey.algorithm)
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

    override suspend fun sign(
        data: ByteArray,
        privateKey: PrivateRsaKey<RsaAlgorithm.RsaSignatureAlgorithm>
    ): ByteArray {
        TODO()
    }

    override suspend fun verifySignature(
        signature: ByteArray,
        data: ByteArray,
        publicKey: PublicRsaKey<RsaAlgorithm.RsaSignatureAlgorithm>
    ): Boolean {
        TODO("Not yet implemented")
    }
}
