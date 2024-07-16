package com.icure.kryptom.utils

class PackedBytesReader(
    private val data: ByteArray,
) {
    private var position = 0

    fun readNext(size: Int): ByteArray {
        if (position + size > data.size) {
            throw IllegalArgumentException("Not enough bytes left")
        }
        return data.sliceArray(position until position + size).also {
            position += size
        }
    }

    fun ensureComplete(): Unit {
        if (position < data.size) {
            throw IllegalStateException("Did not complete reading")
        }
    }
}