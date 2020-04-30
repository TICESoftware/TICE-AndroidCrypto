package com.ticeapp.ticeandroidcrypto

class ConversationState(
    val userId: UserId,
    val conversationId: ConversationId,
    val rootKey: SecretKey,
    val rootChainPublicKey: PublicKey,
    val rootChainPrivateKey: PrivateKey,
    val rootChainRemotePublicKey: PublicKey?,
    val sendingChainKey: SecretKey?,
    val receivingChainKey: SecretKey?,
    val sendMessageNumber: Int,
    val receivedMessageNumber: Int,
    val previousSendingChanLength: Int,
    val messageKeyCache: String
)