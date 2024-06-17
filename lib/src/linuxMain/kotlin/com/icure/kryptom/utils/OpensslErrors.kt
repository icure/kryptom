package com.icure.kryptom.utils

import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.addressOf
import kotlinx.cinterop.pin
import libcrypto.ERR_error_string_n
import libcrypto.ERR_load_CRYPTO_strings
import libcrypto.ERR_load_ERR_strings
import libcrypto.OPENSSL_init_crypto

@OptIn(ExperimentalForeignApi::class)
object OpensslErrorHandling {
    private const val SUCCESS_CODE = 1
    private val BUFFER_SIZE = 256.toULong()
    private val errorStringBuffer = ByteArray(BUFFER_SIZE.toInt()).pin()

    fun Int.ensureEvpSuccess(operation: String? = null) {
        if (this != SUCCESS_CODE) {
            ERR_error_string_n(this.toULong(), errorStringBuffer.addressOf(0), BUFFER_SIZE)
            val errorString = errorStringBuffer.get().decodeToString().takeWhile { it.code != 0 }
            throw PlatformMethodException(
                if (operation != null) "$operation failed - $errorString" else errorString,
                this
            )
        }
    }
}

/**
 * Represents an unexpected error that occurred while using a platform method.
 * This could happen if the method returns an error code or if the result of the method does not conform to the
 * format expected by this library.
 */
class PlatformMethodException(
    message: String,
    val errorCode: Int?
) : Exception(message)
