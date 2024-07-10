package com.icure.kryptom.crypto

import com.icure.kryptom.crypto.BCryptProperty.BlockChainingModeProperty.settingValue
import com.icure.kryptom.utils.PlatformMethodException
import com.icure.kryptom.utils.ensureSuccess
import kotlinx.cinterop.alloc
import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.IntVar
import kotlinx.cinterop.MemScope
import kotlinx.cinterop.addressOf
import kotlinx.cinterop.memScoped
import kotlinx.cinterop.ptr
import kotlinx.cinterop.reinterpret
import kotlinx.cinterop.sizeOf
import kotlinx.cinterop.usePinned
import kotlinx.cinterop.value
import kotlinx.cinterop.wcstr
import platform.windows.BCRYPT_ALG_HANDLE
import platform.windows.BCRYPT_ALG_HANDLEVar
import platform.windows.BCRYPT_HANDLE
import platform.windows.BCryptCloseAlgorithmProvider
import platform.windows.BCryptGetProperty
import platform.windows.BCryptOpenAlgorithmProvider
import platform.windows.BCryptSetProperty

@OptIn(ExperimentalForeignApi::class)
fun <T> withAlgorithmHandle(
    algorithm: BCryptAlgorithm,
    vararg properties: BCryptPropertyWithValue<*>,
    flag: Int = 0,
    block: (BCRYPT_ALG_HANDLE) -> T
): T {
    require(properties.distinctBy { it.property.propertyIdentifier }.size == properties.size) {
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
        val handleValue = handle.value
            ?: throw PlatformMethodException("BCryptOpenAlgorithmProvider successful but handle is null", null)
        properties.forEach { prop ->
            prop.setIn(this, handleValue)
        }
        try {
            block(handleValue)
        } finally {
            BCryptCloseAlgorithmProvider(handleValue, 0.toUInt())
        }
    }
}

@OptIn(ExperimentalForeignApi::class)
fun <V> BCRYPT_HANDLE.getBCryptProperty(property: BCryptProperty<V>): V =
    property.gettingValue { resultBuffer, resultBufferSize, scope ->
        val writtenSize = scope.alloc<IntVar>()
        BCryptGetProperty(
            this,
            property.propertyIdentifier,
            resultBuffer,
            resultBufferSize.toUInt(),
            writtenSize.ptr.reinterpret(),
            0.toUInt()
        ).ensureSuccess("BCryptGetProperty")
        writtenSize.value
    }

@OptIn(ExperimentalForeignApi::class)
data class BCryptPropertyWithValue<V>(
    val property: BCryptProperty<V>,
    val value: V,
) {
    fun setIn(
        scope: MemScope,
        handle: BCRYPT_HANDLE
    ) {
        val (ptr, size) = property.settingValue(scope, value)
        BCryptSetProperty(
            handle,
            property.propertyIdentifier,
            ptr,
            size.toUInt(),
            0.toUInt()
        ).ensureSuccess("BCryptSetProperty of ${property.propertyIdentifier}")
    }
}

infix fun <V> BCryptProperty<V>.setTo(value: V) = BCryptPropertyWithValue(this, value)