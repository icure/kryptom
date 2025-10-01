package com.icure.kryptom.crypto

import com.icure.kryptom.crypto.AesService.Companion.IV_BYTE_LENGTH
import com.icure.kryptom.crypto.AesService.Companion.aesEncryptedSizeFor
import com.icure.kryptom.utils.PlatformMethodException
import kotlinx.cinterop.MemScope
import kotlinx.cinterop.Pinned
import kotlinx.cinterop.ULongVar
import kotlinx.cinterop.addressOf
import kotlinx.cinterop.alloc
import kotlinx.cinterop.memScoped
import kotlinx.cinterop.ptr
import kotlinx.cinterop.usePinned
import kotlinx.cinterop.value
import platform.CoreCrypto.CCCryptorCreateWithMode
import platform.CoreCrypto.CCCryptorFinal
import platform.CoreCrypto.CCCryptorRefVar
import platform.CoreCrypto.CCCryptorRelease
import platform.CoreCrypto.CCCryptorUpdate
import platform.CoreCrypto.kCCAlgorithmAES
import platform.CoreCrypto.kCCDecrypt
import platform.CoreCrypto.kCCEncrypt
import platform.CoreCrypto.kCCKeySizeAES128
import platform.CoreCrypto.kCCKeySizeAES256
import platform.CoreCrypto.kCCModeCBC
import platform.CoreCrypto.kCCModeCTR
import platform.CoreCrypto.kCCOptionPKCS7Padding
import platform.CoreCrypto.kCCSuccess

object IosAesService : AesService {
	override suspend fun <A : AesAlgorithm> generateKey(algorithm: A, size: AesService.KeySize): AesKey<A> =
		AesKey(
			IosStrongRandom.randomBytes(size.byteSize),
			algorithm
		)

	override suspend fun exportKey(key: AesKey<*>): ByteArray =
		key.rawKey.copyOf()

	override suspend fun <A : AesAlgorithm> loadKey(algorithm: A, bytes: ByteArray): AesKey<A> =
		AesKey(
			bytes.copyOf(),
			algorithm
		)

	override suspend fun encrypt(data: ByteArray, key: AesKey<*>, iv: ByteArray?): ByteArray {
		if (iv != null) require(iv.size == IV_BYTE_LENGTH) {
			"Initialization vector must be $IV_BYTE_LENGTH bytes long (got ${iv.size})."
		}
		val generatedIv = iv ?: IosStrongRandom.randomBytes(IV_BYTE_LENGTH)
		val outBytes = generatedIv.copyOf(IV_BYTE_LENGTH + aesEncryptedSizeFor(data.size))
		return memScoped {
			data.usePinned { pinnedData ->
				generatedIv.usePinned { pinnedIv ->
					outBytes.usePinned { pinnedOut ->
						key.rawKey.usePinned { pinnedKey ->
							val cryptor = alloc<CCCryptorRefVar>()
							CCCryptorCreateWithMode(
								kCCEncrypt,
								getCcMode(key.algorithm),
								kCCAlgorithmAES,
								kCCOptionPKCS7Padding,
								pinnedIv.addressOf(0),
								pinnedKey.addressOf(0),
								validateAndGetKeySize(key),
								null,
								0.toULong(),
								0,
								0.toUInt(),
								cryptor.ptr
							).also {
								if (it != kCCSuccess) throw PlatformMethodException(
									"CCCryptorCreateWithMode (encrypt) failed with error code: $it",
									it
								)
							}
							try {
								val dataOutMoved = alloc<ULongVar>()
								var totalMoved = 0
								CCCryptorUpdate(
									cryptor.value,
									pinnedData.addressOf(0),
									data.size.toULong(),
									pinnedOut.addressOf(IV_BYTE_LENGTH),
									(outBytes.size - IV_BYTE_LENGTH).toULong(),
									dataOutMoved.ptr
								).also {
									if (it != kCCSuccess) throw PlatformMethodException(
										"CCCryptorUpdate (encrypt) failed with error code: $it",
										it
									)
								}
								totalMoved += dataOutMoved.value.toInt()
								CCCryptorFinal(
									cryptor.value,
									pinnedOut.addressOf(IV_BYTE_LENGTH + totalMoved),
									(outBytes.size - IV_BYTE_LENGTH - totalMoved).toULong(),
									dataOutMoved.ptr
								).also {
									if (it != kCCSuccess) throw PlatformMethodException(
										"CCCryptorFinal (encrypt) failed with error code: $it",
										it
									)
								}
								totalMoved += dataOutMoved.value.toInt()
								if (totalMoved != (outBytes.size - IV_BYTE_LENGTH)) throw PlatformMethodException(
									"Expected ${outBytes.size - IV_BYTE_LENGTH} encrypted bytes but got $totalMoved",
									null
								)
								outBytes
							} finally {
								CCCryptorRelease(cryptor.value)
							}
						}
					}
				}
			}
		}
	}

	override suspend fun decrypt(ivAndEncryptedData: ByteArray, key: AesKey<*>): ByteArray {
		return memScoped {
			ivAndEncryptedData.usePinned { pinnedIvAndEncryptedData ->
				key.rawKey.usePinned { pinnedKey ->
					doDecrypt(
						algorithm = key.algorithm,
						pinnedEncryptedData = pinnedIvAndEncryptedData,
						encryptedDataOffset = IV_BYTE_LENGTH,
						encryptedDataSize = ivAndEncryptedData.size - IV_BYTE_LENGTH,
						pinnedIv = pinnedIvAndEncryptedData,
						pinnedKey = pinnedKey,
						keySize = validateAndGetKeySize(key)
					)
				}
			}
		}
	}

	override suspend fun decrypt(
		encryptedData: ByteArray,
		key: AesKey<*>,
		iv: ByteArray
	): ByteArray {
		require(iv.size == IV_BYTE_LENGTH) { "IV must be 16 bytes long" }
		return memScoped {
			encryptedData.usePinned { pinnedEncryptedData ->
				iv.usePinned { pinnedIv ->
					key.rawKey.usePinned { pinnedKey ->
						doDecrypt(
							algorithm = key.algorithm,
							pinnedEncryptedData = pinnedEncryptedData,
							encryptedDataOffset = 0,
							encryptedDataSize = encryptedData.size,
							pinnedIv = pinnedIv,
							pinnedKey = pinnedKey,
							keySize = validateAndGetKeySize(key)
						)
					}
				}
			}
		}
	}

	private fun MemScope.doDecrypt(
		algorithm: AesAlgorithm,
		pinnedEncryptedData: Pinned<ByteArray>,
		encryptedDataOffset: Int,
		encryptedDataSize: Int,
		pinnedIv: Pinned<ByteArray>,
		pinnedKey: Pinned<ByteArray>,
		keySize: ULong,
	): ByteArray {
		val cryptor = alloc<CCCryptorRefVar>()
		CCCryptorCreateWithMode(
			kCCDecrypt,
			getCcMode(algorithm),
			kCCAlgorithmAES,
			kCCOptionPKCS7Padding,
			pinnedIv.addressOf(0),
			pinnedKey.addressOf(0),
			keySize,
			null,
			0.toULong(),
			0,
			0.toUInt(),
			cryptor.ptr
		).also {
			// Refer to Applications/Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS.sdk/usr/include/CommonCrypto/CommonCryptoError.h
			if (it != kCCSuccess) throw PlatformMethodException(
				"CCCryptorCreateWithMode (decrypt) failed with error code: $it",
				it
			)
		}
		return try {
			val outBuffer = ByteArray(encryptedDataSize)
			val dataOutMoved = alloc<ULongVar>()
			var totalMoved = 0
			outBuffer.usePinned { pinnedOut ->
				CCCryptorUpdate(
					cryptor.value,
					pinnedEncryptedData.addressOf(encryptedDataOffset),
					encryptedDataSize.toULong(),
					pinnedOut.addressOf(0),
					encryptedDataSize.toULong(),
					dataOutMoved.ptr
				).also {
					if (it != kCCSuccess) throw PlatformMethodException(
						"CCCryptorUpdate (decrypt) failed with error code: $it",
						it
					)
				}
				totalMoved += dataOutMoved.value.toInt()
				CCCryptorFinal(
					cryptor.value,
					pinnedOut.addressOf(totalMoved),
					(outBuffer.size - totalMoved).toULong(),
					dataOutMoved.ptr
				).also {
					if (it != kCCSuccess) throw PlatformMethodException(
						"CCCryptorFinal (decrypt) failed with error code: $it",
						it
					)
				}
				totalMoved += dataOutMoved.value.toInt()
			}
			outBuffer.copyOf(totalMoved)
		} finally {
			CCCryptorRelease(cryptor.value)
		}
	}

	private fun validateAndGetKeySize(key: AesKey<*>): ULong = when (key.rawKey.size) {
		AesService.KeySize.Aes128.byteSize -> kCCKeySizeAES128.toULong()
		// AesCryptoService.KeySize.AES_192.byteSize.toULong() -> kCCKeySizeAES192.toULong()
		AesService.KeySize.Aes256.byteSize -> kCCKeySizeAES256.toULong()
		else -> throw IllegalArgumentException("Invalid size for key: ${key.rawKey.size}")
	}

	private fun getCcMode(
		algorithm: AesAlgorithm
	): UInt = when (algorithm) {
		AesAlgorithm.CbcWithPkcs7Padding -> kCCModeCBC
	}
}