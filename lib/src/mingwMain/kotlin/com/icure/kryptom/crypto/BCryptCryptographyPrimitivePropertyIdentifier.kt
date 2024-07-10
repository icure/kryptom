package com.icure.kryptom.crypto

// https://learn.microsoft.com/en-us/windows/win32/seccng/cng-property-identifiers
interface BCryptProperty {
    val propertyIdentifier: String
    val valueIdentifier: String

    enum class BlockChainingMode(
        override val valueIdentifier: String
    ) : BCryptProperty {
        BCRYPT_CHAIN_MODE_CBC("ChainingModeCBC"),
        BCRYPT_CHAIN_MODE_CCM("ChainingModeCCM"),
        BCRYPT_CHAIN_MODE_CFB("ChainingModeCFB"),
        BCRYPT_CHAIN_MODE_ECB("ChainingModeECB"),
        BCRYPT_CHAIN_MODE_GCM("ChainingModeGCM"),
        BCRYPT_CHAIN_MODE_NA("ChainingModeN/A");

        companion object {
            private const val PROPERTY_IDENTIFIER = "ChainingMode"
        }

        override val propertyIdentifier: String get() = PROPERTY_IDENTIFIER
    }
}