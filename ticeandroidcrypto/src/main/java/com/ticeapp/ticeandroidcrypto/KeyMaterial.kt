package com.ticeapp.ticeandroidcrypto

typealias SecretKey = ByteArray
typealias PrivateKey = ByteArray
typealias PublicKey = ByteArray

class KeyPair(val privateKey: PrivateKey, val publicKey: PublicKey)
class UserPublicKeys(val signingKey: PublicKey, val identityKey: PublicKey, val signedPrekey: PublicKey, val prekeySignature: Signature, val oneTimePrekeys: List<PublicKey>)