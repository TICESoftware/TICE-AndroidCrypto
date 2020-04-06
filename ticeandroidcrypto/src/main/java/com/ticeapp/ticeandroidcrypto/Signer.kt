package com.ticeapp.ticeandroidcrypto

import com.ticeapp.ticeandroidmodels.PrivateKey

interface Signer {
    val privateSigningKey: PrivateKey
}