package com.icure.kryptom.crypto

import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.addressOf
import kotlinx.cinterop.usePinned
import libcrypto.RAND_bytes
import libcrypto.RAND_priv_bytes

@OptIn(ExperimentalForeignApi::class)
object OpensslStrongRandom : StrongRandom {
    override fun fill(array: ByteArray) {
        array.asUByteArray().usePinned {
            RAND_bytes(it.addressOf(0), array.size)
        }
    }

    fun randomPrivateBytes(size: Int) =
        ByteArray(size).also {
            it.asUByteArray().usePinned {
                RAND_priv_bytes(it.addressOf(0), size)
            }
        }
}
