package com.ticeapp.ticeandroidcrypto

import android.util.Base64
import com.goterl.lazycode.lazysodium.LazySodiumAndroid
import com.goterl.lazycode.lazysodium.SodiumAndroid
import com.goterl.lazycode.lazysodium.interfaces.AEAD
import com.ticeapp.androiddoubleratchet.*
import com.ticeapp.androidhkdf.deriveHKDFKey
import com.ticeapp.androidx3dh.X3DH
import io.jsonwebtoken.Jwts
import io.jsonwebtoken.PrematureJwtException
import kotlinx.serialization.*
import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.json.Json
import java.security.KeyPairGenerator
import java.security.spec.ECGenParameterSpec
import java.util.*
import kotlin.collections.HashMap

typealias JWTId = UUID

open class CryptoManager(val cryptoStore: CryptoStore?): CryptoManagerType {
    companion object {
        private const val INFO = "TICE"
        private const val MAX_SKIP = 100
        private const val MAX_CACHE = 100
        private const val ONE_TIME_PREKEY_COUNT = 100
        private const val SIGNING_ALGORITHM = "SHA512withECDSA"
        private const val CERTIFICATES_VALID_FOR = 60*60*24*30*6
        private const val JWT_VALIDATION_LEEWAY = 3
    }

    private val sodium = LazySodiumAndroid(SodiumAndroid())
    private val handshake: X3DH
        get() = X3DH()

    private val doubleRatchets: HashMap<Conversation, DoubleRatchet> = HashMap()

    // Conversation states

    @UnstableDefault
    @ImplicitReflectionSerializer
    private suspend fun saveConversationState(conversation: Conversation) {
        val sessionState = doubleRatchets[conversation]?.sessionState ?: return

        val serializedMessageKeyCache = Json.stringify(sessionState.messageKeyCacheState)
        val conversationState = ConversationState(
            conversation.userId,
            conversation.conversationId,
            sessionState.rootKey.dataKey(),
            sessionState.rootChainKeyPair.publicKey.dataKey(),
            sessionState.rootChainKeyPair.secretKey.dataKey(),
            sessionState.rootChainRemotePublicKey?.dataKey(),
            sessionState.sendingChainKey?.dataKey(),
            sessionState.receivingChainKey?.dataKey(),
            sessionState.sendMessageNumber,
            sessionState.receivedMessageNumber,
            sessionState.previousSendingChainLength,
            serializedMessageKeyCache
        )

        cryptoStore?.saveConversationState(conversationState)
    }

    @UnstableDefault
    @ExperimentalStdlibApi
    @ImplicitReflectionSerializer
    override suspend fun reloadConversationStates() {
        val cryptoStore = cryptoStore ?: throw CryptoManagerError.CryptoStoreNotFoundException()
        for (conversationState in cryptoStore.loadConversationStates()) {
            val rootChainKeyPair = KeyPair(conversationState.rootChainPrivateKey, conversationState.rootChainPublicKey).cryptoKeyPair()
            val messageKeyCacheState: MessageKeyCacheState = Json.parse(ListSerializer(MessageKeyCacheEntry.serializer()), conversationState.messageKeyCache)
            val sessionState = SessionState(
                conversationState.rootKey.cryptoKey(),
                rootChainKeyPair,
                conversationState.rootChainRemotePublicKey?.cryptoKey(),
                conversationState.sendingChainKey?.cryptoKey(),
                conversationState.receivingChainKey?.cryptoKey(),
                conversationState.sendMessageNumber,
                conversationState.receivedMessageNumber,
                conversationState.previousSendingChanLength,
                messageKeyCacheState,
                INFO,
                MAX_SKIP,
                MAX_CACHE
            )

            val conversation = Conversation(conversationState.userId, conversationState.conversationId)
            val doubleRatchet = DoubleRatchet(sessionState, sodium)

            doubleRatchets[conversation] = doubleRatchet
        }
    }

    // Key generation

    override fun generateDatabaseKey(length: Int): SecretKey = sodium.randomBytesBuf(length)

    @ExperimentalStdlibApi
    override fun generateSigningKeyPair(): KeyPair {
        val ecSpec = ECGenParameterSpec("secp521r1")
        val keyPairGenerator = KeyPairGenerator.getInstance("EC")
        keyPairGenerator.initialize(ecSpec)
        val keyPair = keyPairGenerator.generateKeyPair()

        return keyPair.dataKeyPair()
    }

    override fun generateGroupKey(): SecretKey = sodium.keygen(AEAD.Method.XCHACHA20_POLY1305_IETF).dataKey()

    // Membership certificates

    override fun createUserSignedMembershipCertificate(userId: UserId, groupId: GroupId, admin: Boolean, signerUserId: UserId, signer: Signer): Certificate =
        createMembershipCertificate(JWTId.randomUUID(), userId, groupId, admin, JWTIssuer.User(signerUserId), signer.privateSigningKey)

    private fun createMembershipCertificate(jwtId: JWTId, userId: UserId, groupId: GroupId, admin: Boolean, issuer: JWTIssuer, signingKey: PrivateKey): Certificate {
        val issueDate = Date()

        val calendar = Calendar.getInstance()
        calendar.time = issueDate
        calendar.add(Calendar.SECOND, CERTIFICATES_VALID_FOR)
        val expirationDate = calendar.time

        return Jwts.builder()
            .setId(jwtId.uuidString())
            .setIssuer(issuer.claimString())
            .setSubject(userId.uuidString())
            .setIssuedAt(issueDate)
            .setExpiration(expirationDate)
            .claim("groupId", groupId.uuidString())
            .claim("admin", admin)
            .signWith(signingKey.signingKey())
            .compact()
    }

    @ExperimentalStdlibApi
    override fun validateUserSignedMembershipCertificate(certificate: Certificate, membership: Membership, issuer: UserType) = validate(certificate, membership, JWTIssuer.User(issuer.userId), issuer.publicSigningKey)

    @ExperimentalStdlibApi
    override fun validateServerSignedMembershipCertificate(certificate: Certificate, membership: Membership, publicKey: PublicKey) = validate(certificate, membership, JWTIssuer.Server, publicKey)

    @ExperimentalStdlibApi
    private fun validate(certificate: Certificate, membership: Membership, issuer: JWTIssuer, publicKey: PublicKey) {
        val jwts = Jwts
            .parserBuilder()
            .requireSubject(membership.userId.uuidString())
            .requireIssuer(issuer.claimString())
            .require("groupId", membership.groupId.uuidString())
            .require("admin", membership.admin)
            .setAllowedClockSkewSeconds(JWT_VALIDATION_LEEWAY.toLong())
            .setSigningKey(publicKey.verificationKey())
            .build()
            .parseClaimsJws(certificate)

        if (jwts.body.issuedAt.after(Date())) {
            throw PrematureJwtException(jwts.header, jwts.body, "JWT seems to be issued in the future.")
        }
    }

    override fun tokenKeyForGroup(groupKey: SecretKey, user: UserType): SecretKey {
        var inputKeyingMaterial = groupKey.clone()
        inputKeyingMaterial += user.publicSigningKey.clone()

        return deriveHKDFKey(inputKeyingMaterial, L = 32)
    }

    // Handshake

    override suspend fun generateHandshakeKeyMaterial(signer: Signer, publicSigningKey: PublicKey): UserPublicKeys {
        val identityKeyPair = handshake.generateIdentityKeyPair()
        cryptoStore?.saveIdentityKeyPair(identityKeyPair.dataKeyPair())

        return renewHandshakeKeyMaterial(signer, publicSigningKey, renewSignedPrekey = true)
    }

    override suspend fun renewHandshakeKeyMaterial(signer: Signer, publicSigningKey: PublicKey, renewSignedPrekey: Boolean): UserPublicKeys {
        val cryptoStore = cryptoStore ?: throw CryptoManagerError.CryptoStoreNotFoundException()

        val identityKeyPair = cryptoStore.loadIdentityKeyPair()

        val prekeyPair: KeyPair
        val prekeySignature: Signature
        if (renewSignedPrekey) {
            val signedPrekeyPair = handshake.generateSignedPrekeyPair { sign(it.asBytes, signer) }

            prekeyPair = signedPrekeyPair.keyPair.dataKeyPair()
            prekeySignature = signedPrekeyPair.signature

            cryptoStore.savePrekeyPair(prekeyPair, prekeySignature)
        } else {
            prekeyPair = cryptoStore.loadPrekeyPair()
            prekeySignature = cryptoStore.loadPrekeySignature()
        }

        val oneTimePrekeyPairs = handshake.generateOneTimePrekeyPairs(ONE_TIME_PREKEY_COUNT).map(com.goterl.lazycode.lazysodium.utils.KeyPair::dataKeyPair)
        cryptoStore.saveOneTimePrekeyPairs(oneTimePrekeyPairs)

        return UserPublicKeys(publicSigningKey, identityKeyPair.publicKey, prekeyPair.publicKey, prekeySignature, oneTimePrekeyPairs.map(KeyPair::publicKey))
    }

    override fun conversationInitialized(userId: UserId, conversationId: ConversationId): Boolean {
        val conversation = Conversation(userId, conversationId)
        return doubleRatchets.containsKey(conversation)
    }

    @OptIn(UnstableDefault::class)
    @ExperimentalStdlibApi
    override fun conversationFingerprint(ciphertext: Ciphertext): ConversationFingerprint {
        val message = Json.parse(MessageSerializer, ciphertext.decodeToString())
        return Base64.encodeToString(message.header.publicKey.asBytes, Base64.DEFAULT)
    }

    @UnstableDefault
    @ImplicitReflectionSerializer
    @ExperimentalStdlibApi
    override suspend fun initConversation(
        userId: UserId,
        conversationId: ConversationId,
        remoteIdentityKey: PublicKey,
        remoteSignedPrekey: PublicKey,
        remotePrekeySignature: Signature,
        remoteOneTimePrekey: PublicKey?,
        remoteSigningKey: PublicKey
    ): ConversationInvitation {
        val cryptoStore = cryptoStore ?: throw CryptoManagerError.CryptoStoreNotFoundException()

        val identityKeyPair = cryptoStore.loadIdentityKeyPair()
        val prekey = cryptoStore.loadPrekeyPair().publicKey

        val keyAgreementInitiation = handshake.initiateKeyAgreement(
            remoteIdentityKey.cryptoKey(),
            remoteSignedPrekey.cryptoKey(),
            remotePrekeySignature,
            remoteOneTimePrekey?.cryptoKey(),
            identityKeyPair.cryptoKeyPair(),
            prekey.cryptoKey(),
            { verify(it, remoteSignedPrekey, remoteSigningKey) },
            INFO
        )

        val doubleRatchet = DoubleRatchet(null, remoteSignedPrekey.cryptoKey(), keyAgreementInitiation.sharedSecret, MAX_SKIP, MAX_CACHE, INFO, sodium)
        val conversation = Conversation(userId, conversationId)

        doubleRatchets[conversation] = doubleRatchet
        saveConversationState(conversation)

        return ConversationInvitation(identityKeyPair.publicKey, keyAgreementInitiation.ephemeralPublicKey.dataKey(), remoteOneTimePrekey)
    }

    @UnstableDefault
    @ImplicitReflectionSerializer
    @ExperimentalStdlibApi
    override suspend fun processConversationInvitation(conversationInvitation: ConversationInvitation, userId: UserId, conversationId: ConversationId) {
        val cryptoStore = cryptoStore ?: throw CryptoManagerError.CryptoStoreNotFoundException()

        val publicOneTimePrekey = conversationInvitation.usedOneTimePrekey ?: throw CryptoManagerError.OneTimePrekeyMissingException()
        val privateOneTimePrekey = cryptoStore.loadPrivateOneTimePrekey(publicOneTimePrekey)

        val identityKeyPair = cryptoStore.loadIdentityKeyPair().cryptoKeyPair()
        val prekeyPair = cryptoStore.loadPrekeyPair().cryptoKeyPair()
        val oneTimePrekeyPair = KeyPair(privateOneTimePrekey, publicOneTimePrekey).cryptoKeyPair()

        val sharedSecret = handshake.sharedSecretFromKeyAgreement(conversationInvitation.identityKey.cryptoKey(), conversationInvitation.ephemeralKey.cryptoKey(), oneTimePrekeyPair, identityKeyPair, prekeyPair, INFO)

        val doubleRatchet = DoubleRatchet(prekeyPair, null, sharedSecret, MAX_SKIP, MAX_CACHE, INFO, sodium)
        val conversation = Conversation(userId, conversationId)

        doubleRatchets[conversation] = doubleRatchet
        saveConversationState(conversation)

        cryptoStore.deleteOneTimePrekeyPair(publicOneTimePrekey)
    }

    // Encryption / Decryption

    override fun encrypt(data: ByteArray): Pair<Ciphertext, SecretKey> {
        val secretKey = sodium.keygen(AEAD.Method.XCHACHA20_POLY1305_IETF)
        val ciphertext = encrypt(data, secretKey.dataKey())
        return Pair(ciphertext, secretKey.dataKey())
    }

    override fun encrypt(data: ByteArray, secretKey: SecretKey): Ciphertext {
        val nonce = sodium.nonce(AEAD.XCHACHA20POLY1305_IETF_NPUBBYTES)
        val cipher = ByteArray(data.size + AEAD.XCHACHA20POLY1305_IETF_ABYTES)
        sodium.cryptoAeadXChaCha20Poly1305IetfEncrypt(cipher, null, data, data.size.toLong(), null, 0, null, nonce, secretKey)

        return nonce + cipher
    }

    override fun decrypt(encryptedData: ByteArray, secretKey: SecretKey): ByteArray {
        val nonce = encryptedData.sliceArray(0 until AEAD.XCHACHA20POLY1305_IETF_NPUBBYTES)
        val cipher = encryptedData.sliceArray(AEAD.XCHACHA20POLY1305_IETF_NPUBBYTES until encryptedData.size)

        val plaintextLength = cipher.size - AEAD.XCHACHA20POLY1305_IETF_ABYTES
        val plaintext = ByteArray(plaintextLength)
        sodium.cryptoAeadXChaCha20Poly1305IetfDecrypt(plaintext, null, null, cipher, cipher.size.toLong(), null, 0, nonce, secretKey)

        return plaintext
    }

    @UnstableDefault
    @ExperimentalStdlibApi
    @ImplicitReflectionSerializer
    override suspend fun encrypt(data: ByteArray, userId: UserId, conversationId: ConversationId): Ciphertext {
        val conversation = Conversation(userId, conversationId)
        val doubleRatchet = doubleRatchets[conversation] ?: throw CryptoManagerError.ConversationNotInitializedException()

        val message = doubleRatchet.encrypt(data)
        saveConversationState(conversation)

        return Json.stringify(MessageSerializer, message).encodeToByteArray()
    }

    @UnstableDefault
    @ImplicitReflectionSerializer
    @ExperimentalStdlibApi
    suspend fun decrypt(encryptedMessage: Ciphertext, userId: UserId, conversationId: ConversationId): ByteArray {
        val encryptedRawMessage = Json.parse(MessageSerializer, encryptedMessage.decodeToString())
        val conversation = Conversation(userId, conversationId)
        val doubleRatchet = doubleRatchets[conversation] ?: throw CryptoManagerError.ConversationNotInitializedException()

        val plaintext = doubleRatchet.decrypt(encryptedRawMessage)

        saveConversationState(conversation)

        return plaintext
    }

    @UnstableDefault
    @ImplicitReflectionSerializer
    @ExperimentalStdlibApi
    override suspend fun decrypt(encryptedData: Ciphertext, encryptedSecretKey: Ciphertext, userId: UserId, conversationId: ConversationId): ByteArray {
        val secretKey = decrypt(encryptedSecretKey, userId, conversationId)
        return decrypt(encryptedData, secretKey)
    }

    // Auth signature

    override fun generateAuthHeader(signingKey: PrivateKey, userId: UserId): Certificate {
        val issueDate = Date()

        val calendar = Calendar.getInstance()
        calendar.time = issueDate
        calendar.add(Calendar.SECOND, 120)
        val expirationDate = calendar.time

        val nonce = sodium.nonce(16)

        return Jwts.builder()
            .setIssuer(userId.uuidString())
            .setIssuedAt(issueDate)
            .setExpiration(expirationDate)
            .claim("nonce", nonce)
            .signWith(signingKey.signingKey())
            .compact()
    }

    // Signing / verifying

    private fun sign(prekey: PublicKey, signer: Signer): Signature {
        val signingInstance = java.security.Signature.getInstance(SIGNING_ALGORITHM)
        signingInstance.initSign(signer.privateSigningKey.signingKey())
        signingInstance.update(prekey)
        return signingInstance.sign()
    }

    @ExperimentalStdlibApi
    private fun verify(prekeySignature: Signature, prekey: PublicKey, verificationPublicKey: PublicKey): Boolean {
        val verifyingInstance = java.security.Signature.getInstance(SIGNING_ALGORITHM)
        verifyingInstance.initVerify(verificationPublicKey.verificationKey())
        verifyingInstance.update(prekey)
        return verifyingInstance.verify(prekeySignature)
    }
}