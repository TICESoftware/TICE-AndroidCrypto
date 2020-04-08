package com.ticeapp.ticeandroidcrypto

import com.ticeapp.ticeandroidmodels.UserId

internal sealed class JWTIssuer {
    internal object Server : JWTIssuer()
    internal data class User(val userId: UserId) : JWTIssuer()

    fun claimString(): String = when(this) {
        Server -> "server"
        is User -> this.userId.toString()
    }
}