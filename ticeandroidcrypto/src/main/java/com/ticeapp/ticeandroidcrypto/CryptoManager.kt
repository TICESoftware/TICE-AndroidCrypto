package com.ticeapp.ticeandroidcrypto

import android.util.Base64
import com.goterl.lazycode.lazysodium.LazySodiumAndroid
import com.goterl.lazycode.lazysodium.SodiumAndroid
import com.goterl.lazycode.lazysodium.interfaces.AEAD
import com.goterl.lazycode.lazysodium.utils.Key
import com.ticeapp.androiddoubleratchet.*
import com.ticeapp.androidx3dh.X3DH
import com.ticeapp.ticeandroidmodels.*
import com.ticeapp.ticeandroidmodels.PrivateKey
import io.jsonwebtoken.Jwts
import kotlinx.serialization.*
import kotlinx.serialization.json.Json
import java.security.KeyPairGenerator
import java.security.spec.ECGenParameterSpec
import java.util.*
import kotlin.collections.HashMap

typealias JWTId = UUID

class CryptoManager(val cryptoStore: CryptoStore?) {
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
    private val handshake = X3DH()

    private val doubleRatchets: HashMap<Conversation, DoubleRatchet> = HashMap()

    // Conversation states

    @ImplicitReflectionSerializer
    private fun saveConversationState(conversation: Conversation) {
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

    @ExperimentalStdlibApi
    @ImplicitReflectionSerializer
    fun reloadConversationStates() {
        val cryptoStore = cryptoStore ?: throw CryptoManagerError.CryptoStoreNotFoundException()
        for (conversationState in cryptoStore.loadConversationStates()) {
            val rootChainKeyPair = KeyPair(conversationState.rootChainPrivateKey, conversationState.rootChainPublicKey).cryptoKeyPair()
            val messageKeyCacheState: MessageKeyCacheState = Json.parse(conversationState.messageKeyCache)
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
            val doubleRatchet = DoubleRatchet(sessionState)

            doubleRatchets[conversation] = doubleRatchet
        }
    }

    // Key generation

    @ExperimentalStdlibApi
    fun generateSigningKeyPair(): KeyPair {
        val ecSpec = ECGenParameterSpec("secp521r1")
        val keyPairGenerator = KeyPairGenerator.getInstance("EC")
        keyPairGenerator.initialize(ecSpec)
        val keyPair = keyPairGenerator.generateKeyPair()

        return keyPair.dataKeyPair()
    }

    // Membership certificates

    fun createUserSignedMembershipCertificate(userId: UserId, groupId: GroupId, admin: Boolean, signerUserId: UserId, signer: Signer): Certificate =
        createMembershipCertificate(JWTId.randomUUID(), userId, groupId, admin, JWTIssuer.User(signerUserId), signer.privateSigningKey)

    private fun createMembershipCertificate(jwtId: JWTId, userId: UserId, groupId: GroupId, admin: Boolean, issuer: JWTIssuer, signingKey: PrivateKey): Certificate {
        val issueDate = Date()

        val calendar = Calendar.getInstance()
        calendar.time = issueDate
        calendar.add(Calendar.SECOND, CERTIFICATES_VALID_FOR)
        val expirationDate = calendar.time

        val nonce = sodium.nonce(16)

        return Jwts.builder()
            .setId(jwtId.toString())
            .setIssuer(issuer.claimString)
            .setSubject(userId.toString())
            .setIssuedAt(issueDate)
            .setExpiration(expirationDate)
            .claim("groupId", groupId.toString())
            .claim("admin", admin)
            .signWith(signingKey.signingKey())
            .compact()
    }

    @ExperimentalStdlibApi
    fun validateUserSignedMembershipCertificate(certificate: Certificate, membership: Membership, issuer: User) = validate(certificate, membership, JWTIssuer.User(issuer.userId), issuer.publicSigningKey)

    @ExperimentalStdlibApi
    fun validateServerSignedMembershipCertificate(certificate: Certificate, membership: Membership, publicKey: PublicKey) = validate(certificate, membership, JWTIssuer.Server, publicKey)

    @ExperimentalStdlibApi
    private fun validate(certificate: Certificate, membership: Membership, issuer: JWTIssuer, publicKey: PublicKey) {
        Jwts
            .parserBuilder()
            .requireSubject(membership.userId.toString())
            .requireIssuer(issuer.claimString)
            .require("groupId", membership.groupId.toString())
            .require("admin", membership.admin)
            .setAllowedClockSkewSeconds(JWT_VALIDATION_LEEWAY.toLong())
            .setSigningKey(publicKey.verificationKey())
            .build()
            .parseClaimsJws(certificate)
    }
    // Handshake

    fun generateHandshakeKeyMaterial(signer: Signer) {
        val identityKeyPair = handshake.generateIdentityKeyPair()
        cryptoStore?.saveIdentityKeyPair(identityKeyPair.dataKeyPair())
    }

    fun renewHandshakeKeyMaterial(signer: Signer, renewSignedPrekey: Boolean): UserPublicKeys {
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

        // TODO: Signing key
        val publicSigningKey = ByteArray(0)

        return UserPublicKeys(publicSigningKey, identityKeyPair.publicKey, prekeyPair.publicKey, prekeySignature, oneTimePrekeyPairs.map(KeyPair::publicKey))
    }

    @ImplicitReflectionSerializer
    @ExperimentalStdlibApi
    fun initConversation(
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

        val doubleRatchet = DoubleRatchet(null, remoteSignedPrekey.cryptoKey(), keyAgreementInitiation.sharedSecret, MAX_SKIP, MAX_CACHE, INFO)
        val conversation = Conversation(userId, conversationId)

        doubleRatchets[conversation] = doubleRatchet
        saveConversationState(conversation)

        return ConversationInvitation(identityKeyPair.publicKey, keyAgreementInitiation.ephemeralPublicKey.dataKey(), remoteOneTimePrekey)
    }

    @ImplicitReflectionSerializer
    @ExperimentalStdlibApi
    fun processConversationInvitation(conversationInvitation: ConversationInvitation, userId: UserId, conversationId: ConversationId) {
        val cryptoStore = cryptoStore ?: throw CryptoManagerError.CryptoStoreNotFoundException()

        val publicOneTimePrekey = conversationInvitation.usedOneTimePrekey ?: throw CryptoManagerError.OneTimePrekeyMissingException()
        val privateOneTimePrekey = cryptoStore.loadPrivateOneTimePrekey(publicOneTimePrekey)

        val identityKeyPair = cryptoStore.loadIdentityKeyPair().cryptoKeyPair()
        val prekeyPair = cryptoStore.loadPrekeyPair().cryptoKeyPair()
        val oneTimePrekeyPair = KeyPair(privateOneTimePrekey, publicOneTimePrekey).cryptoKeyPair()

        val sharedSecret = handshake.sharedSecretFromKeyAgreement(conversationInvitation.identityKey.cryptoKey(), conversationInvitation.ephemeralKey.cryptoKey(), oneTimePrekeyPair, identityKeyPair, prekeyPair, INFO)

        val doubleRatchet = DoubleRatchet(prekeyPair, null, sharedSecret, MAX_SKIP, MAX_CACHE, INFO)
        val conversation = Conversation(userId, conversationId)

        doubleRatchets[conversation] = doubleRatchet
        saveConversationState(conversation)

        cryptoStore.deleteOneTimePrekeyPair(publicOneTimePrekey)
    }

    // Encryption / Decryption

    fun encrypt(data: ByteArray): Pair<Ciphertext, SecretKey> {
        val secretKey = sodium.keygen(AEAD.Method.XCHACHA20_POLY1305_IETF)
        val ciphertext = encrypt(data, secretKey)
        return Pair(ciphertext, secretKey.dataKey())
    }

    fun encrypt(data: ByteArray, secretKey: Key): Ciphertext {
        val nonce = sodium.nonce(AEAD.XCHACHA20POLY1305_IETF_NPUBBYTES)
        val cipher = ByteArray(data.size + AEAD.XCHACHA20POLY1305_IETF_ABYTES)
        sodium.cryptoAeadXChaCha20Poly1305IetfEncrypt(cipher, null, data, data.size.toLong(), null, 0, null, nonce, secretKey.asBytes)

        return cipher
    }

    fun decrypt(encryptedData: ByteArray, secretKey: SecretKey): ByteArray {
        val nonce = encryptedData.sliceArray(0 until AEAD.XCHACHA20POLY1305_IETF_NPUBBYTES)
        val cipher = encryptedData.sliceArray(AEAD.XCHACHA20POLY1305_IETF_NPUBBYTES until encryptedData.size)

        val plaintextLength = encryptedData.size - AEAD.XCHACHA20POLY1305_IETF_ABYTES
        val plaintext = ByteArray(plaintextLength)
        sodium.cryptoAeadXChaCha20Poly1305IetfDecrypt(plaintext, null, null, cipher, cipher.size.toLong(), null, 0, nonce, secretKey)

        return plaintext
    }

    @ExperimentalStdlibApi
    @ImplicitReflectionSerializer
    fun encrypt(data: ByteArray, userId: UserId, conversationId: ConversationId): Ciphertext {
        val conversation = Conversation(userId, conversationId)
        val doubleRatchet = doubleRatchets[conversation] ?: throw CryptoManagerError.ConversationNotInitializedException()

        val message = doubleRatchet.encrypt(data)
        saveConversationState(conversation)

        return Json.stringify(message).encodeToByteArray()
    }

    @ImplicitReflectionSerializer
    @ExperimentalStdlibApi
    private fun decrypt(encryptedMessage: Message, userId: UserId, conversationId: ConversationId): ByteArray {
        val conversation = Conversation(userId, conversationId)
        val doubleRatchet = doubleRatchets[conversation] ?: throw CryptoManagerError.ConversationNotInitializedException()

        val plaintext = doubleRatchet.decrypt(encryptedMessage)

        saveConversationState(conversation)

        return plaintext
    }

    @ImplicitReflectionSerializer
    @ExperimentalStdlibApi
    fun decrypt(encryptedData: Ciphertext, encryptedSecretKey: Ciphertext, userId: UserId, conversationId: ConversationId): ByteArray {
        val encryptedSecretKeyMessage = Json.parse<Message>(encryptedSecretKey.decodeToString())
        val secretKey = decrypt(encryptedSecretKeyMessage, userId, conversationId)
        return decrypt(encryptedData, secretKey)
    }

    // Auth signature

    fun generateAuthHeader(signingKey: PrivateKey, userId: UserId): Certificate {
        val issueDate = Date()

        val calendar = Calendar.getInstance()
        calendar.time = issueDate
        calendar.add(Calendar.SECOND, 120)
        val expirationDate = calendar.time

        val nonce = sodium.nonce(16)

        return Jwts.builder()
            .setIssuer(userId.toString())
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
        return verifyingInstance.verify(Base64.decode(prekeySignature, Base64.DEFAULT))
    }
}