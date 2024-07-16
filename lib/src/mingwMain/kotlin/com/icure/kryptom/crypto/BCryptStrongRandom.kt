package com.icure.kryptom.crypto

import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.addressOf
import kotlinx.cinterop.reinterpret
import kotlinx.cinterop.usePinned
import platform.windows.BCryptGenRandom

@OptIn(ExperimentalForeignApi::class)
object BCryptStrongRandom : StrongRandom {
    override fun fill(array: ByteArray) {
        array.usePinned {
            BCryptGenRandom(
                null,
                it.addressOf(0).reinterpret(),
                array.size.toUInt(),
                2.toUInt()
            )
        }
    }
}