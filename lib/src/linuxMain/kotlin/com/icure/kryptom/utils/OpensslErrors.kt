package com.icure.kryptom.utils

import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.addressOf
import kotlinx.cinterop.pin
import libcrypto.ERR_error_string_n
import libcrypto.ERR_peek_error
import libcrypto.ERR_print_errors

@OptIn(ExperimentalForeignApi::class)
object OpensslErrorHandling {
    private const val SUCCESS_CODE = 1
    private val BUFFER_SIZE = 256.toULong()
    private val errorStringBuffer = ByteArray(BUFFER_SIZE.toInt()).pin()

    fun Int.ensureEvpSuccess(operation: String? = null) {
        if (this != SUCCESS_CODE) {
            throwExceptionForCode(this, operation)
        }
    }

    fun throwExceptionForCode(
        errorCode: Int,
        operation: String? = null
    ): Nothing {
        val errorMessage = buildString {
            if (operation != null) {
                append(operation)
                append(" failed\n")
            }
            if (errorCode != 0) {
                append("error_string_n: ")
                ERR_error_string_n(errorCode.toULong(), errorStringBuffer.addressOf(0), BUFFER_SIZE)
                append(errorStringBuffer.get().decodeToString().takeWhile { it.code != 0 })
                append("\n")
            }
            if (ERR_peek_error() != 0.toULong()) {
                append("error_queue:\n")
                append(writingToBio { ERR_print_errors(it) }.decodeToString().takeWhile { it.code != 0 })
            }
        }
        throw PlatformMethodException(
            errorMessage,
            errorCode
        )
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
