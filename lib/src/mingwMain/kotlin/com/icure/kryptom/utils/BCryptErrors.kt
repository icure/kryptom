package com.icure.kryptom.utils

import platform.windows.NTSTATUS

fun NTSTATUS.ensureSuccess(operation: String) {
    if (this != 0) throw PlatformMethodException(
        "$operation gave error ${this.toUInt().toString(16)}",
        this
    )
}

/**
 * Represents an unexpected error that occurred while using a platform method.
 * This could happen if the method returns an error code or if the result of the method does not conform to the
 * format expected by this library.
 */
class PlatformMethodException(
    message: String,
    /**
     * Refer to https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-erref/596a1078-e883-4972-9bbc-49e60bebca55
     */
    val errorCode: Int?
) : Exception(message)
