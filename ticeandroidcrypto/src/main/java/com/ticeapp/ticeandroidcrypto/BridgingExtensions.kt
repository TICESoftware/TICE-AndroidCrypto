package com.ticeapp.ticeandroidcrypto

import android.util.Base64
import com.goterl.lazycode.lazysodium.utils.Key
import com.ticeapp.ticeandroidmodels.PrivateKey
import com.ticeapp.ticeandroidmodels.PublicKey
import java.security.KeyFactory
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import java.security.PrivateKey as SigningKey
import java.security.PublicKey as VerificationKey
import java.security.KeyPair as SecurityKeyPair
import com.goterl.lazycode.lazysodium.utils.KeyPair as CryptoKeyPair
import com.ticeapp.ticeandroidmodels.KeyPair as ModelsKeyPair

fun CryptoKeyPair.dataKeyPair(): ModelsKeyPair = ModelsKeyPair(secretKey.asBytes, publicKey.asBytes)
fun ModelsKeyPair.cryptoKeyPair(): CryptoKeyPair = CryptoKeyPair(Key.fromBytes(publicKey), Key.fromBytes(privateKey))

fun Key.dataKey(): ByteArray = asBytes
fun ByteArray.cryptoKey(): Key = Key.fromBytes(this)

fun PrivateKey.signingKey(): SigningKey = KeyFactory.getInstance("EC").generatePrivate(PKCS8EncodedKeySpec(this))
@ExperimentalStdlibApi fun PublicKey.verificationKey(): VerificationKey {
    val publicKeyString =
        decodeToString()
            .removePrefix("-----BEGIN PUBLIC KEY-----")
            .removeSuffix("-----END PUBLIC KEY-----")
    return KeyFactory.getInstance("EC").generatePublic(X509EncodedKeySpec(Base64.decode(publicKeyString, Base64.DEFAULT)))
}

@ExperimentalStdlibApi fun VerificationKey.dataKey(): PublicKey {
    val publicKeyHeader = "-----BEGIN PUBLIC KEY-----"
    val publicKey = Base64.encodeToString(encoded, Base64.DEFAULT)
    val publicKeyFooter = "-----END PUBLIC KEY-----"

    val publicKeyString = publicKeyHeader + publicKey + publicKeyFooter
    return publicKeyString.encodeToByteArray()
}

@ExperimentalStdlibApi fun SecurityKeyPair.dataKeyPair(): ModelsKeyPair = ModelsKeyPair(private.encoded, public.dataKey())
