package com.icure.kryptom.crypto

import com.icure.kryptom.utils.OpensslErrorHandling.ensureEvpSuccess
import com.icure.kryptom.utils.PlatformMethodException
import kotlinx.cinterop.CArrayPointer
import kotlinx.cinterop.CValue
import kotlinx.cinterop.CVariable
import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.NativePlacement
import kotlinx.cinterop.addressOf
import kotlinx.cinterop.alloc
import kotlinx.cinterop.allocArray
import kotlinx.cinterop.allocArrayOf
import kotlinx.cinterop.cstr
import kotlinx.cinterop.get
import kotlinx.cinterop.memScoped
import kotlinx.cinterop.pin
import kotlinx.cinterop.pointed
import kotlinx.cinterop.ptr
import kotlinx.cinterop.toCValues
import kotlinx.cinterop.value
import libcrypto.EVP_MAC_CTX_free
import libcrypto.EVP_MAC_CTX_new
import libcrypto.EVP_MAC_fetch
import libcrypto.EVP_MAC_final
import libcrypto.EVP_MAC_free
import libcrypto.EVP_MAC_init
import libcrypto.EVP_MAC_update
import libcrypto.EVP_MAX_MD_SIZE
import libcrypto.OSSL_LIB_CTX_free
import libcrypto.OSSL_LIB_CTX_new
import libcrypto.OSSL_PARAM
import libcrypto.OSSL_PARAM_construct_end
import libcrypto.OSSL_PARAM_construct_utf8_string

@OptIn(ExperimentalForeignApi::class)
object OpensslHmacService : HmacService {
    override suspend fun <A : HmacAlgorithm> generateKey(algorithm: A, keySize: Int?): HmacKey<A> {
        require(keySize == null || keySize >= algorithm.minimumKeySize) {
            "Invalid key size for $algorithm. A minimal length of ${algorithm.minimumKeySize} is required"
        }
        return HmacKey(OpensslStrongRandom.randomPrivateBytes(keySize ?: algorithm.recommendedKeySize), algorithm)
    }

    override suspend fun exportKey(key: HmacKey<*>): ByteArray =
        key.rawKey

    override suspend fun <A : HmacAlgorithm> loadKey(algorithm: A, bytes: ByteArray): HmacKey<A> {
        require(bytes.size >= algorithm.minimumKeySize) {
            "Invalid key length for algorithm $algorithm: got ${bytes.size} but at least ${algorithm.minimumKeySize} expected"
        }
        return HmacKey(bytes.copyOf(), algorithm)
    }

    private fun digestNameForAlgorithm(alg: HmacAlgorithm) = when (alg) {
		HmacAlgorithm.HmacSha256 -> "sha256"
		HmacAlgorithm.HmacSha512 -> "sha512"
	}

    override suspend fun sign(data: ByteArray, key: HmacKey<*>): ByteArray = memScoped {
        val digestName = digestNameForAlgorithm(key.algorithm)
        val libCtx = OSSL_LIB_CTX_new()
        val mac = libCtx?.let { EVP_MAC_fetch(it, "HMAC", null) }
        val ctx = mac?.let { EVP_MAC_CTX_new(it) }
        try {
            if (ctx == null) throw PlatformMethodException("HMAC context initialization failed", null)

            val rawKey = key.rawKey.asUByteArray().pin()
            val pinnedData = data.asUByteArray().pin()
            val output = ByteArray(EVP_MAX_MD_SIZE)
            val pinnedOutput = output.asUByteArray().pin()
            val outLength = alloc(0.toULong())
            val params = allocArray<OSSL_PARAM>(2)
            // For a DSL can check https://github.com/whyoleg/cryptography-kotlin/blob/28457b8e16111b45ba55d708fda3939260932003/cryptography-providers/openssl3/api/src/commonMain/kotlin/internal/arrays.kt#L1-L27
            OSSL_PARAM_construct_utf8_string("digest", digestName.cstr, digestName.length.toULong()).place(params[0].ptr)
            OSSL_PARAM_construct_end().place(params[1].ptr)
            try {
                EVP_MAC_init(ctx, rawKey.addressOf(0), key.rawKey.size.toULong(), params).ensureEvpSuccess("EVP_MAC_init")
                EVP_MAC_update(ctx, pinnedData.addressOf(0), data.size.toULong())
                EVP_MAC_final(ctx, null, outLength.ptr, 0.toULong()).ensureEvpSuccess("EVP_MAC_final (get size)")
                check(outLength.value == output.size.toULong()) { "Unexpected output size - expected ${output.size}, required ${outLength.value}" }
                EVP_MAC_final(ctx, pinnedOutput.addressOf(0), outLength.ptr, output.size.toULong()).ensureEvpSuccess("EVP_MAC_final")
                check(outLength.value == output.size.toULong()) { "Unexpected output size written - expected ${output.size}, written ${outLength.value}" }
                output
            } finally {
                pinnedData.unpin()
                pinnedOutput.unpin()
            }
        } finally {
            EVP_MAC_CTX_free(ctx);
            EVP_MAC_free(mac);
            OSSL_LIB_CTX_free(libCtx);
        }
    }

    override suspend fun verify(signature: ByteArray, data: ByteArray, key: HmacKey<*>): Boolean {
        val currentSignature = sign(data, key)
        return signature.contentEquals(currentSignature)
    }
}
