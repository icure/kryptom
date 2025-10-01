package com.icure.kryptom.crypto

import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.security.Security
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec
import kotlin.random.Random

actual fun initCryptoProvider() {
	Security.addProvider(BouncyCastleProvider())
}
