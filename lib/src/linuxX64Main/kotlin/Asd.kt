import kotlinx.cinterop.ExperimentalForeignApi
import libcrypto.AES_MAXNR

@OptIn(ExperimentalForeignApi::class)
fun main() {
	println(AES_MAXNR)
}
