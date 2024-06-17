import com.icure.kryptom.crypto.AesAlgorithm
import com.icure.kryptom.crypto.AesService
import com.icure.kryptom.crypto.HmacAlgorithm
import com.icure.kryptom.crypto.OpensslAesService
import com.icure.kryptom.crypto.OpensslDigestService
import com.icure.kryptom.crypto.OpensslHmacService
import com.icure.kryptom.crypto.OpensslRsaService
import com.icure.kryptom.crypto.OpensslStrongRandom
import com.icure.kryptom.crypto.RsaAlgorithm
import io.ktor.util.encodeBase64
import kotlinx.coroutines.runBlocking

@OptIn(ExperimentalStdlibApi::class)
fun main(): Unit = runBlocking {
	val keypair = OpensslRsaService.generateKeyPair(RsaAlgorithm.RsaEncryptionAlgorithm.OaepWithSha1)
	println(keypair.private.pemPkcs8Key)
	println(keypair.public.pemSpkiKey)
	val encrypted = OpensslRsaService.encrypt("Something to encrypt".encodeToByteArray(), keypair.public)
	println(encrypted.toHexString())
	println(OpensslRsaService.decrypt(encrypted, keypair.private).decodeToString())
//	val key = OpensslAesService.generateKey(AesAlgorithm.CbcWithPkcs7Padding, AesService.KeySize.Aes256)
//	val data = "Something to encrypt".encodeToByteArray()
//	val iv = OpensslStrongRandom.randomBytes(16)
//	println(OpensslAesService.encrypt(data, key, iv).toHexString())
//	println(OpensslAesService.encrypt(data, key, iv).toHexString())
//	val hmacKey = OpensslHmacService.generateKey(HmacAlgorithm.HmacSha512)
//	val signature = OpensslHmacService.sign(data, hmacKey)
//	println(OpensslHmacService.sign(data, hmacKey))
//	println(OpensslHmacService.verify(signature, data, hmacKey))

}
