package com.ticeapp.ticeandroidcrypto

typealias Data = ByteArray

interface CryptoManagerType {
    fun reloadConversationStates()

    fun generateDatabaseKey(length: Int): SecretKey
    fun generateSigningKeyPair(): KeyPair
    fun generateGroupKey(): SecretKey

    fun createUserSignedMembershipCertificate(
        userId: UserId,
        groupId: GroupId,
        admin: Boolean,
        signerUserId: UserId,
        signer: Signer
    ): Certificate

    fun validateUserSignedMembershipCertificate(certificate: Certificate, membership: Membership, issuer: UserType)
    fun validateServerSignedMembershipCertificate(certificate: Certificate, membership: Membership, publicKey: PublicKey)

    fun tokenKeyForGroup(groupKey: SecretKey, user: UserType): SecretKey

    fun generateHandshakeKeyMaterial(signer: Signer, publicSigningKey: PublicKey): UserPublicKeys
    fun renewHandshakeKeyMaterial(signer: Signer, publicSigningKey: PublicKey, renewSignedPrekey: Boolean): UserPublicKeys

    fun conversationInitialized(userId: UserId, conversationId: ConversationId): Boolean
    fun conversationFingerprint(ciphertext: Ciphertext): ConversationFingerprint
    fun initConversation(
        userId: UserId,
        conversationId: ConversationId,
        remoteIdentityKey: PublicKey,
        remoteSignedPrekey: PublicKey,
        remotePrekeySignature: Signature,
        remoteOneTimePrekey: PublicKey?,
        remoteSigningKey: PublicKey
    ): ConversationInvitation

    fun processConversationInvitation(conversationInvitation: ConversationInvitation, userId: UserId, conversationId: ConversationId)

    fun encrypt(data: Data): Pair<Ciphertext, SecretKey>
    fun encrypt(data: Data, secretKey: SecretKey): Ciphertext
    fun encrypt(data: Data, userId: UserId, conversationId: ConversationId): Ciphertext
    fun decrypt(encryptedData: Data, secretKey: SecretKey): Data
    fun decrypt(encryptedData: Data, encryptedSecretKey: Data, userId: UserId, conversationId: ConversationId): Data

    fun generateAuthHeader(signingKey: PrivateKey, userId: UserId): Certificate
}