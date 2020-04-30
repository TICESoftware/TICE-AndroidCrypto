package com.ticeapp.ticeandroidcrypto

interface UserType {
    val userId: UserId
    var publicSigningKey: PublicKey
    var publicName: String?
}