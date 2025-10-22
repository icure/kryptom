package com.icure.kryptom.crypto

import com.icure.kryptom.utils.OpensslErrorHandling.ensureEvpSuccess
import com.icure.kryptom.utils.PlatformMethodException
import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.addressOf
import kotlinx.cinterop.alloc
import kotlinx.cinterop.allocArray
import kotlinx.cinterop.cstr
import kotlinx.cinterop.get
import kotlinx.cinterop.interpretCPointer
import kotlinx.cinterop.memScoped
import kotlinx.cinterop.pin
import kotlinx.cinterop.pointed
import kotlinx.cinterop.ptr
import kotlinx.cinterop.value
import libcrypto.EVP_MAC_CTX_free
import libcrypto.EVP_MAC_CTX_new
import libcrypto.EVP_MAC_fetch
import libcrypto.EVP_MAC_final
import libcrypto.EVP_MAC_free
import libcrypto.EVP_MAC_init
import libcrypto.EVP_MAC_update
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
		HmacAlgorithm.HmacSha256 -> "SHA-256"
		HmacAlgorithm.HmacSha512 -> "SHA-512"
	}

    override suspend fun sign(data: ByteArray, key: HmacKey<*>): ByteArray = memScoped {
        val digestName = digestNameForAlgorithm(key.algorithm)
        val mac = EVP_MAC_fetch(null, "HMAC", null)
        val ctx = mac?.let { EVP_MAC_CTX_new(it) }
        try {
            if (ctx == null) throw PlatformMethodException("HMAC context initialization failed", null)

            val rawKey = key.rawKey.asUByteArray().pin()
            val pinnedData = data.asUByteArray().pin()
            val output = ByteArray(key.algorithm.digestSize)
            val pinnedOutput = output.asUByteArray().pin()
            val outLength = alloc(0.toULong())
            // For a DSL to setup OSSL_PARAM can check https://github.com/whyoleg/cryptography-kotlin/blob/28457b8e16111b45ba55d708fda3939260932003/cryptography-providers/openssl3/api/src/commonMain/kotlin/internal/arrays.kt#L1-L27
            val params = allocArray<OSSL_PARAM>(2)
            OSSL_PARAM_construct_utf8_string(null, digestName.cstr.ptr, digestName.length.toULong()).place(params[0].ptr)
            OSSL_PARAM_construct_end().place(params[1].ptr)
            interpretCPointer<OSSL_PARAM>(params[0].ptr.rawValue)!!.pointed.key = "digest".cstr.ptr // TODO Should be able to set it in OSSL_PARAM_construct_utf8_string, but passing a normal string doesn't work, and kotlin doesn't compile if passing cstr.ptr
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
            EVP_MAC_CTX_free(ctx)
            EVP_MAC_free(mac)
        }
    }

    override suspend fun verify(signature: ByteArray, data: ByteArray, key: HmacKey<*>): Boolean {
        val currentSignature = sign(data, key)
        return signature.contentEquals(currentSignature)
    }
}
