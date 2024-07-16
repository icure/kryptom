package com.icure.kryptom.crypto

import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.IntVar
import kotlinx.cinterop.MemScope
import kotlinx.cinterop.addressOf
import kotlinx.cinterop.alloc
import kotlinx.cinterop.memScoped
import kotlinx.cinterop.ptr
import kotlinx.cinterop.reinterpret
import kotlinx.cinterop.sizeOf
import kotlinx.cinterop.toKStringFromUtf16
import kotlinx.cinterop.usePinned
import kotlinx.cinterop.utf16
import kotlinx.cinterop.value
import platform.posix.wchar_tVar
import platform.windows.PUCHAR

// https://learn.microsoft.com/en-us/windows/win32/seccng/cng-property-identifiers
@OptIn(ExperimentalForeignApi::class)
sealed interface BCryptProperty<V> {
    val propertyIdentifier: String

    fun settingValue(
        scope: MemScope,
        value: V
    ): Pair<PUCHAR, Int>

    fun gettingValue(
        doGet: (resultBuffer: PUCHAR, resultBufferSize: Int, scope: MemScope) -> Int
    ): V

    object BlockChainingModeProperty : BCryptProperty<BlockChainingModeProperty.BlockChainingMode> {
        enum class BlockChainingMode(val identifier: String) {
            BCRYPT_CHAIN_MODE_CBC("ChainingModeCBC"),
            BCRYPT_CHAIN_MODE_CCM("ChainingModeCCM"),
            BCRYPT_CHAIN_MODE_CFB("ChainingModeCFB"),
            BCRYPT_CHAIN_MODE_ECB("ChainingModeECB"),
            BCRYPT_CHAIN_MODE_GCM("ChainingModeGCM"),
            BCRYPT_CHAIN_MODE_NA("ChainingModeN/A");

            companion object {
                fun fromIdentifier(identifier: String): BlockChainingMode =
                    requireNotNull(entries.firstOrNull { it.identifier == identifier }) {
                        "Invalid identifier: $identifier"
                    }
            }
        }
        private const val RETRIEVE_BUFFER_SIZE = 64

        override val propertyIdentifier: String = "ChainingMode"

        override fun settingValue(
            scope: MemScope,
            value: BlockChainingMode
        ): Pair<PUCHAR, Int> = value.identifier.utf16.let {
            Pair(
                it.getPointer(scope).reinterpret(),
                it.size
            )
        }

        override fun gettingValue(
            doGet: (resultBuffer: PUCHAR, resultBufferSize: Int, scope: MemScope) -> Int
        ): BlockChainingMode = memScoped {
            val resultBuffer = ByteArray(RETRIEVE_BUFFER_SIZE)
            resultBuffer.usePinned { pinnedBuffer ->
                val writtenSize = doGet(pinnedBuffer.addressOf(0).reinterpret(), RETRIEVE_BUFFER_SIZE, this)
                check(writtenSize == RETRIEVE_BUFFER_SIZE) {
                    "Should have written $RETRIEVE_BUFFER_SIZE bytes got $writtenSize"
                }
                val resultString = pinnedBuffer.addressOf(0).reinterpret<wchar_tVar>().toKStringFromUtf16()
                BlockChainingMode.fromIdentifier(resultString)
            }
        }
    }

    object ObjectLengthProperty : BCryptProperty<Int> {
        override val propertyIdentifier: String = "ObjectLength"

        override fun settingValue(scope: MemScope, value: Int): Pair<PUCHAR, Int> {
            throw UnsupportedOperationException("Can't set value for ObjectLengthProperty")
        }

        override fun gettingValue(
            doGet: (resultBuffer: PUCHAR, resultBufferSize: Int, scope: MemScope) -> Int
        ): Int = memScoped {
            val result = alloc<IntVar>()
            val intSize = sizeOf<IntVar>().toInt()
            val writtenSize = doGet(result.ptr.reinterpret(), intSize, this)
            check(writtenSize == intSize) {
                "Should have written $intSize bytes got $writtenSize"
            }
            result.value
        }
    }

}