package com.icure.kryptom.crypto.external

import com.icure.kryptom.crypto.PrivateRsaKey
import com.icure.kryptom.crypto.PrivateRsaKeyJwk
import com.icure.kryptom.crypto.PublicRsaKey
import com.icure.kryptom.crypto.PublicRsaKeyJwk
import com.icure.kryptom.crypto.RsaAlgorithm
import com.icure.kryptom.crypto.RsaKeypair

external interface XRsaKeypair {
	val private: XPrivateRsaKey
	val public: XPublicRsaKey
}

fun <A : RsaAlgorithm> XRsaKeypair.toKryptom(algorithm: A): RsaKeypair<A> {
	return RsaKeypair(private.toKryptom(algorithm), public.toKryptom(algorithm))
}

// TODO switch to @JsPlainObject on kotlin 2
@Suppress("UNUSED_VARIABLE", "UnsafeCastFromDynamic")
fun RsaKeypair<*>.toExternal(): XRsaKeypair {
	val private = this.private.toExternal()
	val public = this.public.toExternal()
	return js("({private: private, public: public})")
}

external interface XPrivateRsaKey {
	val privateKey: dynamic
	val algorithm: String
}

fun <A : RsaAlgorithm> XPrivateRsaKey.toKryptom(algorithm: A): PrivateRsaKey<A> {
	if (this.algorithm != algorithm.identifier) {
		throw AssertionError("Algorithm mismatch: ${this.algorithm} != ${algorithm.identifier}")
	}
	return PrivateRsaKey(privateKey, algorithm)
}

fun XPrivateRsaKey.toKryptom(): PrivateRsaKey<RsaAlgorithm> {
	return PrivateRsaKey(privateKey, RsaAlgorithm.fromIdentifier(algorithm))
}

fun XPrivateRsaKey.toKryptomSignature(): PrivateRsaKey<RsaAlgorithm.RsaSignatureAlgorithm> {
	return PrivateRsaKey(privateKey, RsaAlgorithm.RsaSignatureAlgorithm.fromIdentifier(algorithm))
}

fun XPrivateRsaKey.toKryptomEncryption(): PrivateRsaKey<RsaAlgorithm.RsaEncryptionAlgorithm> {
	return PrivateRsaKey(privateKey, RsaAlgorithm.RsaEncryptionAlgorithm.fromIdentifier(algorithm))
}

// TODO switch to @JsPlainObject on kotlin 2
@Suppress("UNUSED_VARIABLE", "UNCHECKED_CAST_TO_EXTERNAL_INTERFACE")
fun PrivateRsaKey<*>.toExternal(): XPrivateRsaKey {
	val algorithmIdentifier = this.algorithm.identifier
	val thisKey = this.key
	return js("({privateKey: thisKey, algorithm: algorithmIdentifier})") as XPrivateRsaKey
}

external interface XPublicRsaKey {
	val publicKey: dynamic
	val algorithm: String
}

fun <A : RsaAlgorithm> XPublicRsaKey.toKryptom(algorithm: A): PublicRsaKey<A> {
	if (this.algorithm != algorithm.identifier) {
		throw AssertionError("Algorithm mismatch: ${this.algorithm} != ${algorithm.identifier}")
	}
	return PublicRsaKey(publicKey, algorithm)
}

fun XPublicRsaKey.toKryptom(): PublicRsaKey<RsaAlgorithm> {
	return PublicRsaKey(publicKey, RsaAlgorithm.fromIdentifier(algorithm))
}

fun XPublicRsaKey.toKryptomSignature(): PublicRsaKey<RsaAlgorithm.RsaSignatureAlgorithm> {
	return PublicRsaKey(publicKey, RsaAlgorithm.RsaSignatureAlgorithm.fromIdentifier(algorithm))
}

fun XPublicRsaKey.toKryptomEncryption(): PublicRsaKey<RsaAlgorithm.RsaEncryptionAlgorithm> {
	return PublicRsaKey(publicKey, RsaAlgorithm.RsaEncryptionAlgorithm.fromIdentifier(algorithm))
}

// TODO switch to @JsPlainObject on kotlin 2
@Suppress("UNUSED_VARIABLE", "UNCHECKED_CAST_TO_EXTERNAL_INTERFACE")
fun PublicRsaKey<*>.toExternal(): XPublicRsaKey {
	val algorithmIdentifier = this.algorithm.identifier
	val thisKey = this.key
	return js("({publicKey: thisKey, algorithm: algorithmIdentifier})") as XPublicRsaKey
}

fun JsonWebKey.toPrivateJwk() = PrivateRsaKeyJwk(
	alg = requireNotNull(alg) { "alg can't be null for a private JsonWebKey" },
	d = requireNotNull(d) { "d can't be null for a private JsonWebKey" },
	dp = requireNotNull(dp) { "dp can't be null for a private JsonWebKey" },
	dq = requireNotNull(dq) { "dq can't be null for a private JsonWebKey" },
	e = requireNotNull(e) { "e can't be null for a private JsonWebKey" },
	ext = requireNotNull(ext) { "ext can't be null for a private JsonWebKey" },
	key_ops = requireNotNull(key_ops) { "key_ops can't be null for a private JsonWebKey" }.toSet(),
	n = requireNotNull(n) { "n can't be null for a private JsonWebKey" },
	p = requireNotNull(p) { "p can't be null for a private JsonWebKey" },
	q = requireNotNull(q) { "q can't be null for a private JsonWebKey" },
	qi = requireNotNull(qi) { "qi can't be null for a private JsonWebKey" },
)

fun JsonWebKey.toPublicJwk() = PublicRsaKeyJwk(
	alg = requireNotNull(alg) { "alg can't be null for a public JsonWebKey" },
	e = requireNotNull(e) { "e can't be null for a public JsonWebKey" },
	ext = requireNotNull(ext) { "ext can't be null for a public JsonWebKey" },
	key_ops = requireNotNull(key_ops) { "key_ops can't be null for a public JsonWebKey" }.toSet(),
	n = requireNotNull(n) { "n can't be null for a public JsonWebKey" },
)

@Suppress("UNCHECKED_CAST_TO_EXTERNAL_INTERFACE", "UNUSED_VARIABLE")
fun PrivateRsaKeyJwk.toPrivateJwk(): JsonWebKey {
	val alg = alg
	val d = d
	val dp = dp
	val dq = dq
	val e = e
	val ext = ext
	val key_ops = key_ops.toTypedArray()
	val n = n
	val p = p
	val q = q
	val qi = qi
	return js("{alg:alg,d:d,dp:dp,dq:dq,e:e,ext:ext,key_ops:key_ops,n:n,p:p,q:q,qi:qi}") as JsonWebKey
}

@Suppress("UNCHECKED_CAST_TO_EXTERNAL_INTERFACE", "UNUSED_VARIABLE")
fun PublicRsaKeyJwk.toPublicJwk(): JsonWebKey {
	val alg = alg
	val e = e
	val ext = ext
	val key_ops = key_ops.toTypedArray()
	val n = n
	return js("{alg:alg,e:e,ext:ext,key_ops:key_ops,n:n}") as JsonWebKey
}

external interface JsonWebKey {
	val alg: String?
	val d: String?
	val dp: String?
	val dq: String?
	val e: String?
	val ext: Boolean?
	val key_ops: Array<String>?
	val n: String?
	val p: String?
	val q: String?
	val qi: String?
}
