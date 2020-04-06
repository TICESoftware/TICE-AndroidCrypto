package com.ticeapp.ticeandroidcrypto

sealed class CryptoManagerError: Exception() {
    class CryptoStoreNotFoundException: CryptoManagerError()
    class OneTimePrekeyMissingException: CryptoManagerError()
    class ConversationNotInitializedException: CryptoManagerError()
}