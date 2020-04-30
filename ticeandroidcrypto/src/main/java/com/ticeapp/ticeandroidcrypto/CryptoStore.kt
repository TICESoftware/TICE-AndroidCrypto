package com.ticeapp.ticeandroidcrypto

interface CryptoStore {
    fun saveIdentityKeyPair(keyPair: KeyPair)
    fun savePrekeyPair(keyPair: KeyPair, signature: Signature)
    fun saveOneTimePrekeyPairs(keyPairs: List<KeyPair>)
    fun loadIdentityKeyPair(): KeyPair
    fun loadPrekeyPair(): KeyPair
    fun loadPrekeySignature(): Signature
    fun loadPrivateOneTimePrekey(publicKey: PublicKey): PrivateKey
    fun deleteOneTimePrekeyPair(publicKey: PublicKey)

    fun saveConversationState(conversationState: ConversationState)
    fun loadConversationState(userId: UserId, conversationId: ConversationId): ConversationState?
    fun loadConversationStates(): List<ConversationState>
}