package com.ticeapp.ticeandroidcrypto

internal sealed class JWTIssuer {
    internal object Server : JWTIssuer()
    internal data class User(val userId: UserId) : JWTIssuer()

    fun claimString(): String = when(this) {
        Server -> "server"
        is User -> this.userId.toString()
    }
}