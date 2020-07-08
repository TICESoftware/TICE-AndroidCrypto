package com.ticeapp.ticeandroidcrypto

typealias SecretKey = ByteArray
typealias PrivateKey = ByteArray
typealias PublicKey = ByteArray

data class KeyPair(val privateKey: PrivateKey, val publicKey: PublicKey) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as KeyPair

        if (!privateKey.contentEquals(other.privateKey)) return false
        if (!publicKey.contentEquals(other.publicKey)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = privateKey.contentHashCode()
        result = 31 * result + publicKey.contentHashCode()
        return result
    }
}

data class UserPublicKeys(val signingKey: PublicKey, val identityKey: PublicKey, val signedPrekey: PublicKey, val prekeySignature: Signature, val oneTimePrekeys: List<PublicKey>) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as UserPublicKeys

        if (!signingKey.contentEquals(other.signingKey)) return false
        if (!identityKey.contentEquals(other.identityKey)) return false
        if (!signedPrekey.contentEquals(other.signedPrekey)) return false
        if (!prekeySignature.contentEquals(other.prekeySignature)) return false

        if (oneTimePrekeys.size != other.oneTimePrekeys.size) return false
        if ((oneTimePrekeys zip other.oneTimePrekeys).any { !it.first.contentEquals(it.second) }) return false

        return true
    }

    override fun hashCode(): Int {
        var result = signingKey.contentHashCode()
        result = 31 * result + identityKey.contentHashCode()
        result = 31 * result + signedPrekey.contentHashCode()
        result = 31 * result + prekeySignature.contentHashCode()
        result = 31 * result + oneTimePrekeys.hashCode()
        return result
    }
}