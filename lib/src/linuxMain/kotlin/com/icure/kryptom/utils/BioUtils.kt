package com.icure.kryptom.utils

import com.icure.kryptom.utils.OpensslErrorHandling.ensureEvpSuccess
import kotlinx.cinterop.ByteVar
import kotlinx.cinterop.CPointer
import kotlinx.cinterop.CPointerVar
import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.ULongVar
import kotlinx.cinterop.addressOf
import kotlinx.cinterop.alloc
import kotlinx.cinterop.memScoped
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

/**
 * Initializes a bio, executes a lambda that writes something to that bio, then creates a kotlin byte array with the
 * data from the bio and frees the original bio before returning.
 */
@OptIn(ExperimentalForeignApi::class)
fun writingToBio(
    writeToBio: (bio: CPointer<BIO>) -> Unit
): ByteArray = memScoped {
    val bio = BIO_new(BIO_s_mem()) ?: throw PlatformMethodException("Could not initialise bio", null)
    val bioDataStart = alloc<CPointerVar<ByteVar>>()
    try {
        writeToBio(bio)
        val length = BIO_ctrl(bio, BIO_CTRL_INFO, 0, bioDataStart.ptr).toInt()
        check(length >= 0) { "BIO_CTRL_INFO returned $length" }
        if (length == 0) {
            ByteArray(0)
        } else {
            checkNotNull(bioDataStart.value?.readBytes(length)) {
                "BIO data points to null"
            }
        }
    } finally {
        BIO_free_all(bio)
    }
}

/**
 * Initializes a BIO with the content of [data], executes a function that reads from the bio, then frees the bio.
 */
@OptIn(ExperimentalForeignApi::class)
fun <T> readingFromBio(
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
