package com.ticeapp.ticeandroidcrypto

interface CryptoStore {
    suspend fun saveIdentityKeyPair(keyPair: KeyPair)
    suspend fun savePrekeyPair(keyPair: KeyPair, signature: Signature)
    suspend fun saveOneTimePrekeyPairs(keyPairs: List<KeyPair>)
    suspend fun loadIdentityKeyPair(): KeyPair
    suspend fun loadPrekeyPair(): KeyPair
    suspend fun loadPrekeySignature(): Signature
    suspend fun loadPrivateOneTimePrekey(publicKey: PublicKey): PrivateKey
    suspend fun deleteOneTimePrekeyPair(publicKey: PublicKey)

    suspend fun saveConversationState(conversationState: ConversationState)
    suspend fun loadConversationState(userId: UserId, conversationId: ConversationId): ConversationState?
    suspend fun loadConversationStates(): List<ConversationState>
}