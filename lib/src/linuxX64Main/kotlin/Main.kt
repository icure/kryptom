import com.icure.kryptom.crypto.AesAlgorithm
import com.icure.kryptom.crypto.AesService
import com.icure.kryptom.crypto.OpensslAesService
import com.icure.kryptom.crypto.OpensslDigestService
import kotlinx.coroutines.runBlocking

@OptIn(ExperimentalStdlibApi::class)
fun main(): Unit = runBlocking {
	val key = OpensslAesService.generateKey(AesAlgorithm.CbcWithPkcs7Padding, AesService.KeySize.Aes256)
	val data = "Something to encrypt".encodeToByteArray()
	val encrypted = OpensslAesService.encrypt(data, key)
	println(encrypted.toHexString())
	println(OpensslAesService.decrypt(encrypted, key).decodeToString())
	println(OpensslDigestService.sha256(data).toHexString())
	println(OpensslDigestService.sha256(data).toHexString())
	println(OpensslDigestService.sha256(data).toHexString())
}
