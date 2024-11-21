package com.icure.kryptom.crypto

import com.icure.kryptom.utils.OpensslErrorHandling.ensureEvpSuccess
import com.icure.kryptom.utils.PlatformMethodException
import kotlinx.cinterop.CPointer
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
import libcrypto.EVP_MD
import libcrypto.EVP_MD_CTX_free
import libcrypto.EVP_MD_CTX_new
import libcrypto.EVP_sha256
import libcrypto.EVP_sha512

@OptIn(ExperimentalForeignApi::class)
object OpensslDigestService : DigestService {
    override suspend fun sha256(data: ByteArray): ByteArray =
        doSha(data, EVP_sha256(), 32)

    override suspend fun sha512(data: ByteArray): ByteArray =
        doSha(data, EVP_sha512(), 64)

    private fun doSha(
        data: ByteArray,
        type: CPointer<EVP_MD>?,
        digestSize: Int
    ): ByteArray {
        val ctx = EVP_MD_CTX_new() ?: throw PlatformMethodException("Could not initialise context", null)
        val output = ByteArray(digestSize)
        val outputPinned = output.asUByteArray().pin()
        val dataPinned = data.asUByteArray().pin()
        memScoped {
            val written = alloc(0.toUInt())
            try {
                EVP_DigestInit_ex(
                    ctx,
                    type,
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
                check(written.value.toInt() == digestSize) { "Unexpected bytes written for sha256" }
            } finally {
                outputPinned.unpin()
                dataPinned.unpin()
                EVP_MD_CTX_free(ctx)
            }
        }
        return output
    }
}
