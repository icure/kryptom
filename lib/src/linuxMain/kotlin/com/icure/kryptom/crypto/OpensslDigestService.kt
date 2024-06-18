package com.icure.kryptom.crypto

import com.icure.kryptom.utils.OpensslErrorHandling.ensureEvpSuccess
import com.icure.kryptom.utils.PlatformMethodException
import io.ktor.util.Digest
import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.addressOf
import kotlinx.cinterop.alloc
import kotlinx.cinterop.memScoped
import kotlinx.cinterop.pin
import kotlinx.cinterop.ptr
import kotlinx.cinterop.value
import libcrypto.EVP_DigestFinal_ex
import libcrypto.EVP_DigestInit_ex
import libcrypto.EVP_DigestUpdate
import libcrypto.EVP_MD_CTX_free
import libcrypto.EVP_MD_CTX_new
import libcrypto.EVP_sha256

@OptIn(ExperimentalForeignApi::class)
object OpensslDigestService : DigestService {
    override suspend fun sha256(data: ByteArray): ByteArray {
        val ctx = EVP_MD_CTX_new() ?: throw PlatformMethodException("Could not initialise context", null)
        val output = ByteArray(32)
        val outputPinned = output.asUByteArray().pin()
        val dataPinned = data.asUByteArray().pin()
        memScoped {
            val written = alloc(0.toUInt())
            try {
                EVP_DigestInit_ex(
                    ctx,
                    EVP_sha256(),
                    null
                ).ensureEvpSuccess("EVP_DigestInit_ex")
                EVP_DigestUpdate(
                    ctx,
                    dataPinned.addressOf(0),
                    data.size.toULong()
                ).ensureEvpSuccess("EVP_DigestUpdate")
                EVP_DigestFinal_ex(
                    ctx,
                    outputPinned.addressOf(0),
                    written.ptr
                ).ensureEvpSuccess("EVP_DigestFinal_ex")
                check(written.value.toInt() == 32) { "Unexpected bytes written for sha256" }
            } finally {
                outputPinned.unpin()
                dataPinned.unpin()
                EVP_MD_CTX_free(ctx)
            }
        }
        return output
    }
}
