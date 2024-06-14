import com.icure.kryptom.utils.toHexString
import io.ktor.utils.io.core.toByteArray
import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.addressOf
import kotlinx.cinterop.alloc
import kotlinx.cinterop.memScoped
import kotlinx.cinterop.pin
import kotlinx.cinterop.ptr
import kotlinx.cinterop.value
import libcrypto.EVP_CIPHER_CTX_new
import libcrypto.EVP_DecryptFinal_ex
import libcrypto.EVP_DecryptInit_ex
import libcrypto.EVP_DecryptUpdate
import libcrypto.EVP_EncryptFinal_ex
import libcrypto.EVP_EncryptInit_ex
import libcrypto.EVP_EncryptUpdate
import libcrypto.EVP_aes_256_cbc
import kotlin.random.Random

@OptIn(ExperimentalForeignApi::class)
fun main() {
	val ctx = checkNotNull(EVP_CIPHER_CTX_new()) {
		"ctx is null"
	}
	val dCtx = checkNotNull(EVP_CIPHER_CTX_new()) {
		"dCtx is null"
	}
	val iv = Random.nextBytes(16).toUByteArray().pin()
	val toEncrypt = "This is what I need to encrypt".toByteArray().toUByteArray().pin()
	val key = Random.nextBytes(32).toUByteArray().pin()
	val cipherText = UByteArray(32).pin() // Should actually calculate appropriate size depending on input
	val decrypted = UByteArray(128).pin() // TODO Check if using exact size could break (maybe it can if there is padding)
	memScoped {
		val writtenBytes = alloc<Int>(0)
		var totalSizeCiphertext = 0
		var totalSizeDecrypted = 0
		try {
			check(
				EVP_EncryptInit_ex(
					ctx,
					EVP_aes_256_cbc(),
					null,
					key.addressOf(0),
					iv.addressOf(0),
				) == 1
			) { "Failed to init" }
			check(
				EVP_EncryptUpdate(
					ctx,
					cipherText.addressOf(0),
					writtenBytes.ptr,
					toEncrypt.addressOf(0),
					toEncrypt.get().size
				) == 1
			) { "Failed to update" }
			totalSizeCiphertext += writtenBytes.value
			check(
				EVP_EncryptFinal_ex(
					ctx,
					cipherText.addressOf(totalSizeCiphertext),
					writtenBytes.ptr
				) == 1
			) { "Final failed" }
			totalSizeCiphertext += writtenBytes.value
			check(totalSizeCiphertext == 32) { "Unexpected length" }
			println("Encrypted is ${cipherText.get().toHexString()}")

			// Now decrypt
			check(
				EVP_DecryptInit_ex( // TODO check difference between ex and normal
					dCtx,
					EVP_aes_256_cbc(),
					null,
					key.addressOf(0),
					iv.addressOf(0),
				) == 1
			) { "Decrypt init failed" }
			check(
				EVP_DecryptUpdate(
					dCtx,
					decrypted.addressOf(0),
					writtenBytes.ptr,
					cipherText.addressOf(0),
					totalSizeCiphertext
				) == 1
			) { "Decrypt update failed" }
			totalSizeDecrypted += writtenBytes.value
			check(
				EVP_DecryptFinal_ex(
					dCtx,
					decrypted.addressOf(totalSizeDecrypted),
					writtenBytes.ptr
				) == 1
			) { "Decrypt final failed" }
			totalSizeDecrypted += writtenBytes.value
			println("Decrypted is ${decrypted.get().toByteArray().take(totalSizeDecrypted).toByteArray().decodeToString()}")
		} finally {
			iv.unpin()
			key.unpin()
			toEncrypt.unpin()
			cipherText.unpin()
			// TODO proper c cleanup (for ctx and maybe something more?)
		}
	}
}
