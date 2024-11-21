package com.icure.kryptom.crypto

import com.icure.kryptom.utils.PlatformMethodException
import kotlinx.cinterop.ByteVar
import kotlinx.cinterop.CArrayPointer
import kotlinx.cinterop.CPointer
import kotlinx.cinterop.UByteVar
import kotlinx.cinterop.addressOf
import kotlinx.cinterop.allocArray
import kotlinx.cinterop.memScoped
import kotlinx.cinterop.readBytes
import kotlinx.cinterop.toLong
import kotlinx.cinterop.usePinned
import platform.CoreCrypto.CC_SHA256
import platform.CoreCrypto.CC_SHA512

object IosDigestService : DigestService {
	override suspend fun sha256(data: ByteArray): ByteArray =
		doSha(data, 32) { dataAddress, dataSize, out ->  CC_SHA256(dataAddress, dataSize, out) }

	override suspend fun sha512(data: ByteArray): ByteArray =
		doSha(data, 64) { dataAddress, dataSize, out ->  CC_SHA512(dataAddress, dataSize, out) }

	// https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man3/CC_SHA256.3cc.html
	private inline fun doSha(
		data: ByteArray,
		digestLength: Int,
		doSha: (dataAddress: CPointer<ByteVar>, dataSize: UInt, out:  CArrayPointer<UByteVar>) -> CPointer<UByteVar>?
	): ByteArray = memScoped {
		val out = allocArray<UByteVar>(digestLength)
		data.usePinned { pinnedData ->
			val shaResult = doSha(pinnedData.addressOf(0), data.size.toUInt(), out)
			if (shaResult.toLong() != out.toLong()) throw PlatformMethodException(
				"CC_SHAx should have returned the output address but got ${shaResult.toLong()} instead.",
				null
			)
		}
		out.readBytes(digestLength)
	}
}