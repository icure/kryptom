package com.icure.kryptom.crypto

import com.icure.kryptom.crypto.asn.AsnToJwkConverter
import com.icure.kryptom.utils.PackedBytesReader
import com.icure.kryptom.utils.base64UrlDecode
import com.icure.kryptom.utils.base64UrlEncode
import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.addressOf
import kotlinx.cinterop.alloc
import kotlinx.cinterop.memScoped
import kotlinx.cinterop.pointed
import kotlinx.cinterop.ptr
import kotlinx.cinterop.readBytes
import kotlinx.cinterop.reinterpret
import kotlinx.cinterop.sizeOf
import kotlinx.cinterop.usePinned
import platform.posix.read
import platform.windows.BCRYPT_RSAKEY_BLOB

/**
 * Represents a private rsa key. Each key should be used only for a specific algorithm, which is represented by [A].
 */
actual class PrivateRsaKey<out A : RsaAlgorithm>(
    val keyData: BCryptRsaFullPrivateKeyBlob,
    actual val algorithm: A
) : RsaKey


/**
 * Represents a public rsa key. Each key should be used only for a specific algorithm, which is represented by [A].
 */
actual class PublicRsaKey<out A : RsaAlgorithm>(
    val keyData: BCryptRsaPublicKeyBlob,
    actual val algorithm: A
) : RsaKey

/**
 * Represents an aes key.
 */
actual class AesKey<out A : AesAlgorithm>(
    val rawKey: ByteArray,
    actual val algorithm: A
)

actual class HmacKey<out A : HmacAlgorithm>(
    val rawKey: ByteArray,
    actual val algorithm: A
)

@OptIn(ExperimentalForeignApi::class)
data class BCryptRsaKeyHeader(
    val Magic: UInt,
    val BitLength: UInt,
    val cbPublicExp: UInt,
    val cbModulus: UInt,
    val cbPrime1: UInt,
    val cbPrime2: UInt,
) {
    init {
        require(
            Magic == BCRYPT_RSAPUBLIC_MAGIC ||
                Magic == BCRYPT_RSAPRIVATE_MAGIC ||
                Magic == BCRYPT_RSAFULLPRIVATE_MAGIC
        ) {
            "Invalid magic $Magic"
        }
    }

    companion object {
        val STRUCT_SIZE = sizeOf<BCRYPT_RSAKEY_BLOB>().toInt()
        val BCRYPT_RSAPUBLIC_MAGIC = 0x31415352.toUInt()
        val BCRYPT_RSAPRIVATE_MAGIC = 0x32415352.toUInt()
        val BCRYPT_RSAFULLPRIVATE_MAGIC = 0x33415352.toUInt()

        fun fromBytes(bytes: ByteArray) =
            bytes.usePinned {
                require(bytes.size >= STRUCT_SIZE) {
                    "Should be at least $STRUCT_SIZE bytes"
                }
                val blobInfo = it.addressOf(0).reinterpret<BCRYPT_RSAKEY_BLOB>()
                BCryptRsaKeyHeader(
                    blobInfo.pointed.Magic,
                    blobInfo.pointed.BitLength,
                    blobInfo.pointed.cbPublicExp,
                    blobInfo.pointed.cbModulus,
                    blobInfo.pointed.cbPrime1,
                    blobInfo.pointed.cbPrime2
                )
            }
    }

    fun toBytes(): ByteArray =
        memScoped {
            val struct = alloc<BCRYPT_RSAKEY_BLOB>()
            struct.Magic = Magic
            struct.BitLength = BitLength
            struct.cbPublicExp = cbPublicExp
            struct.cbModulus = cbModulus
            struct.cbPrime1 = cbPrime1
            struct.cbPrime2 = cbPrime2
            struct.ptr.readBytes(STRUCT_SIZE)
        }
}

private fun byteArrayToJwkString(bytes: ByteArray): String =
    base64UrlEncode(bytes.let {
        if (it[0] == 0.toByte()) {
            it.dropWhile { b -> b == 0.toByte() }.toByteArray()
        } else it
    }).dropLastWhile { it == '=' }

class BCryptRsaPublicKeyBlob(
    val publicExponent: ByteArray,
    val modulus: ByteArray
) {
    companion object {
        fun fromJwk(jwk: PublicRsaKeyJwk) = BCryptRsaPublicKeyBlob(
            publicExponent = base64UrlDecode(jwk.e),
            modulus = base64UrlDecode(jwk.n),
        )

        fun fromBytes(bytes: ByteArray): BCryptRsaPublicKeyBlob {
            val header = BCryptRsaKeyHeader.fromBytes(bytes)
            require(header.Magic == BCryptRsaKeyHeader.BCRYPT_RSAPUBLIC_MAGIC) {
                "Invalid magic for public key ${header.Magic}"
            }
            val reader = PackedBytesReader(
                bytes.sliceArray(BCryptRsaKeyHeader.STRUCT_SIZE until bytes.size)
            )
            return BCryptRsaPublicKeyBlob(
                reader.readNext(header.cbPublicExp.toInt()),
                reader.readNext(header.cbModulus.toInt())
            ).also {
                reader.ensureComplete()
            }
        }
    }

    fun toSpki(): ByteArray = AsnToJwkConverter.jwkToSpki(
        PublicRsaKeyJwk(
            alg = "Unused",
            e = byteArrayToJwkString(publicExponent),
            n = byteArrayToJwkString(modulus),
            ext = false,
            key_ops = setOf("encrypt")
        )
    )

    internal val packedBytes: ByteArray by lazy {
        val headerBytes = BCryptRsaKeyHeader(
            Magic = BCryptRsaKeyHeader.BCRYPT_RSAPUBLIC_MAGIC,
            BitLength = (modulus.size * 8).toUInt(),
            cbModulus = modulus.size.toUInt(),
            cbPublicExp = publicExponent.size.toUInt(),
            cbPrime1 = 0.toUInt(),
            cbPrime2 = 0.toUInt(),
        ).toBytes()
        headerBytes + publicExponent + modulus
    }
}

class BCryptRsaPrivateKeyBlob(
    val publicExponent: ByteArray,
    val modulus: ByteArray,
    val prime1: ByteArray,
    val prime2: ByteArray,
) {

    internal val packedBytes: ByteArray by lazy {
        val headerBytes = BCryptRsaKeyHeader(
            Magic = BCryptRsaKeyHeader.BCRYPT_RSAPRIVATE_MAGIC,
            BitLength = (modulus.size * 8).toUInt(),
            cbModulus = modulus.size.toUInt(),
            cbPublicExp = publicExponent.size.toUInt(),
            cbPrime1 = prime1.size.toUInt(),
            cbPrime2 = prime2.size.toUInt(),
        ).toBytes()
        headerBytes + publicExponent + modulus + prime1 + prime2
    }
}

class BCryptRsaFullPrivateKeyBlob(
    val publicExponent: ByteArray,
    val modulus: ByteArray,
    val prime1: ByteArray,
    val prime2: ByteArray,
    val exponent1: ByteArray,
    val exponent2: ByteArray,
    val coefficient: ByteArray,
    val privateExponent: ByteArray
) {
    init {
        require(exponent1.size == prime1.size) { "Size mismatch: ${exponent1.size} != ${prime1.size}" }
        require(exponent2.size == prime2.size) { "Size mismatch: ${exponent2.size} != ${prime2.size}" }
        require(coefficient.size == prime1.size) { "Size mismatch: ${coefficient.size} != ${prime1.size}" }
        require(modulus.size == privateExponent.size) { "Size mismatch: ${modulus.size} != ${privateExponent.size}" }
    }

    companion object {
        fun fromJwk(jwk: PrivateRsaKeyJwk): BCryptRsaFullPrivateKeyBlob {
            fun ByteArray.prependWith0ToHaveSize(
                size: Int
            ): ByteArray {
                require(this.size <= size) { "Array size is ${this.size} but want size $size" }
                return if (this.size == size) this else ByteArray(size - this.size) + this
            }
            val rawPublicExponent = base64UrlDecode(jwk.e)
            val rawModulus = base64UrlDecode(jwk.n)
            val rawPrime1 = base64UrlDecode(jwk.p)
            val rawPrime2 = base64UrlDecode(jwk.q)
            val rawExponent1 = base64UrlDecode(jwk.dp)
            val rawExponent2 = base64UrlDecode(jwk.dq)
            val rawCoefficient = base64UrlDecode(jwk.qi)
            val rawPrivateExponent = base64UrlDecode(jwk.d)
            val cbPublicExp = rawPublicExponent.size
            val cbModulus = maxOf(rawModulus.size, rawPrivateExponent.size)
            val cbPrime1 = maxOf(rawPrime1.size, rawExponent1.size, rawCoefficient.size)
            val cbPrime2 = maxOf(rawPrime2.size, rawExponent2.size)
            return BCryptRsaFullPrivateKeyBlob(
                rawPublicExponent.prependWith0ToHaveSize(cbPublicExp),
                rawModulus.prependWith0ToHaveSize(cbModulus),
                rawPrime1.prependWith0ToHaveSize(cbPrime1),
                rawPrime2.prependWith0ToHaveSize(cbPrime2),
                rawExponent1.prependWith0ToHaveSize(cbPrime1),
                rawExponent2.prependWith0ToHaveSize(cbPrime2),
                rawCoefficient.prependWith0ToHaveSize(cbPrime1),
                rawPrivateExponent.prependWith0ToHaveSize(cbModulus),
            )
        }

        fun fromBytes(bytes: ByteArray): BCryptRsaFullPrivateKeyBlob {
            val header = BCryptRsaKeyHeader.fromBytes(bytes)
            require(header.Magic == BCryptRsaKeyHeader.BCRYPT_RSAFULLPRIVATE_MAGIC) {
                "Invalid magic for public key ${header.Magic}"
            }
            val reader = PackedBytesReader(
                bytes.sliceArray(BCryptRsaKeyHeader.STRUCT_SIZE until bytes.size)
            )
            return BCryptRsaFullPrivateKeyBlob(
                publicExponent = reader.readNext(header.cbPublicExp.toInt()),
                modulus = reader.readNext(header.cbModulus.toInt()),
                prime1 = reader.readNext(header.cbPrime1.toInt()),
                prime2 = reader.readNext(header.cbPrime2.toInt()),
                exponent1 = reader.readNext(header.cbPrime1.toInt()),
                exponent2 = reader.readNext(header.cbPrime2.toInt()),
                coefficient = reader.readNext(header.cbPrime1.toInt()),
                privateExponent = reader.readNext(header.cbModulus.toInt()),
            ).also {
                reader.ensureComplete()
            }
        }

    }

    fun toPkcs8(): ByteArray = AsnToJwkConverter.jwkToPkcs8(
        PrivateRsaKeyJwk(
            alg = "Unused",
            e = byteArrayToJwkString(publicExponent),
            n = byteArrayToJwkString(modulus),
            p = byteArrayToJwkString(prime1),
            q = byteArrayToJwkString(prime2),
            dp = byteArrayToJwkString(exponent1),
            dq = byteArrayToJwkString(exponent2),
            qi = byteArrayToJwkString(coefficient),
            d = byteArrayToJwkString(privateExponent),
            ext = false,
            key_ops = setOf("decrypt")
        )
    )

    fun toPublic() = BCryptRsaPublicKeyBlob(
        publicExponent = publicExponent,
        modulus = modulus
    )

    internal val packedBytes: ByteArray by lazy {
        val headerBytes = BCryptRsaKeyHeader(
            Magic = BCryptRsaKeyHeader.BCRYPT_RSAFULLPRIVATE_MAGIC,
            BitLength = (modulus.size * 8).toUInt(),
            cbModulus = modulus.size.toUInt(),
            cbPublicExp = publicExponent.size.toUInt(),
            cbPrime1 = prime1.size.toUInt(),
            cbPrime2 = prime2.size.toUInt(),
        ).toBytes()
        headerBytes + publicExponent + modulus + prime1 + prime2 + exponent1 + exponent2 + coefficient + privateExponent
    }

    internal val minimalPackedBytes: ByteArray by lazy {
        BCryptRsaPrivateKeyBlob(
            publicExponent = publicExponent,
            modulus = modulus,
            prime1 = prime1,
            prime2 = prime2,
        ).packedBytes
    }
}