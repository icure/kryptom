package com.icure.kryptom.utils

/**
 * @param bytes must be 16 bytes long, but this method won't check. Will also be modified in place
 */
@ExperimentalUnsignedTypes
internal fun unsafeUuidFromRandomBytes(bytes: UByteArray): String {
	// Set version 4
	bytes[6] = (bytes[6] and 0x0fu) or 0x40u
	// Set IETF variant
	bytes[8] = (bytes[8] and 0x3fu) or 0x80u
	val s = bytes.toHexString()
	return "${s.substring(0, 8)}-${s.substring(8, 12)}-${s.substring(12, 16)}-${s.substring(16, 20)}-${
		s.substring(
			20
		)
	}"
}