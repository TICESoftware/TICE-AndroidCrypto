package com.ticeapp.ticeandroidcrypto

import com.goterl.lazycode.lazysodium.utils.Key
import com.goterl.lazycode.lazysodium.utils.KeyPair as CryptoKeyPair
import com.ticeapp.ticeandroidmodels.KeyPair as ModelsKeyPair

fun CryptoKeyPair.dataKeyPair(): ModelsKeyPair = ModelsKeyPair(secretKey.asBytes, publicKey.asBytes)
fun ModelsKeyPair.cryptoKeyPair(): CryptoKeyPair = CryptoKeyPair(Key.fromBytes(publicKey), Key.fromBytes(privateKey))

fun Key.dataKey(): ByteArray = asBytes
fun ByteArray.cryptoKey(): Key = Key.fromBytes(this)