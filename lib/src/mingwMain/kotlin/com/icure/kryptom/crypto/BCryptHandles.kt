package com.icure.kryptom.crypto

import com.icure.kryptom.utils.PlatformMethodException
import com.icure.kryptom.utils.ensureSuccess
import kotlinx.cinterop.alloc
import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.addressOf
import kotlinx.cinterop.memScoped
import kotlinx.cinterop.ptr
import kotlinx.cinterop.reinterpret
import kotlinx.cinterop.usePinned
import kotlinx.cinterop.value
import kotlinx.cinterop.wcstr
import platform.windows.BCRYPT_ALG_HANDLE
import platform.windows.BCRYPT_ALG_HANDLEVar
import platform.windows.BCryptCloseAlgorithmProvider
import platform.windows.BCryptOpenAlgorithmProvider
import platform.windows.BCryptSetProperty

@OptIn(ExperimentalForeignApi::class)
fun <T> withAlgorithmHandle(
    algorithm: BCryptAlgorithm,
    vararg properties: BCryptProperty,
    flag: Int = 0,
    block: (BCRYPT_ALG_HANDLE) -> T
): T {
    require(properties.distinctBy { it.propertyIdentifier }.size == properties.size) {
        "Duplicate properties in $properties"
    }
    return memScoped {
        val handle = alloc<BCRYPT_ALG_HANDLEVar>()
        BCryptOpenAlgorithmProvider(
            handle.ptr,
            algorithm.identifier,
            null,
            flag.toUInt()
        ).ensureSuccess("BCryptOpenAlgorithmProvider")
        properties.forEach { prop ->
            BCryptSetProperty(
                handle.value,
                prop.propertyIdentifier,
                prop.valueIdentifier.wcstr.getPointer(memScope).reinterpret(),
                prop.valueIdentifier.length.toUInt(),
                0.toUInt()
            ).ensureSuccess("BCryptSetProperty of ${prop.propertyIdentifier}")
        }
        val handleValue = handle.value
            ?: throw PlatformMethodException("BCryptOpenAlgorithmProvider successful but handle is null", null)
        try {
            block(handleValue)
        } finally {
            BCryptCloseAlgorithmProvider(handleValue, 0.toUInt())
        }
    }
}