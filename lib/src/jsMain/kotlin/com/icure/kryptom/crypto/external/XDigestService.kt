package com.icure.kryptom.crypto.external

import kotlin.js.Promise

external interface XDigestService {
	fun sha256(data: ByteArray): Promise<ByteArray>
}