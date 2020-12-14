package com.ticeapp.ticeandroidcryptoapp

import androidx.appcompat.app.AppCompatActivity
import android.os.Bundle
import com.ticeapp.ticeandroidcrypto.*
import kotlinx.serialization.*
import io.jsonwebtoken.*
import io.jsonwebtoken.security.SignatureException
import kotlinx.coroutines.runBlocking
import java.util.*
import kotlin.collections.HashMap

class MainActivity : AppCompatActivity() {

    val groupId = GroupId.fromString("E621E1F8-C36C-495A-93FC-0C247A3E6E5F")
    val userId = UserId.fromString("F621E1F8-C36C-495A-93FC-0C247A3E6E5F")

    @ExperimentalStdlibApi
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        testLibrary()
    }

    @ExperimentalStdlibApi
    private fun testLibrary() {
        testSigningKeyPairGeneration()
        testUserSignedMembershipCertificate()
        testServerSignedMembershipCertificate()
        testValidateMembershipCertificateInvalidMembership()
        testValidateExpiredCertificate()
        testValidateCertificateIssuedInFuture()
        testValidateCertificateInvalidSignature()
        runBlocking {  testInitializeConversation() }
        testSymmetricEncryptionFixKey()
        testSymmetricEncryptionGeneratedKey()
        testUserPublicKeysComparison()
        testAuthHeader()
    }

    @ExperimentalStdlibApi
    private fun testSigningKeyPairGeneration() {
        val cryptoManager = CryptoManager(null)
        val keyPair = cryptoManager.generateSigningKeyPair()

        val publicKeyString = keyPair.publicKey.decodeToString()
        val lines = publicKeyString.split("\n")

        if (lines.any { it.length > 64 }) {
            throw Exception("Test failed")
        }
    }

    @ExperimentalStdlibApi
    private fun testUserSignedMembershipCertificate() {
        val cryptoManager = CryptoManager(null)
        val keyPair = cryptoManager.generateSigningKeyPair()
        val testUser = TestUser(userId, keyPair.privateKey, keyPair.publicKey, null)

        val certificate = cryptoManager.createUserSignedMembershipCertificate(userId, groupId, true, userId, testUser)
        val membership = Membership(
            userId,
            groupId,
            testUser.publicSigningKey,
            true,
            serverSignedMembershipCertificate = ""
        )
        cryptoManager.validateUserSignedMembershipCertificate(certificate, membership, testUser)
    }

    @ExperimentalStdlibApi
    private fun testServerSignedMembershipCertificate() {
        val cryptoManager = CryptoManager(null)
        val serverKeyPair = cryptoManager.generateSigningKeyPair()

        val issueDate = Date()

        val calendar = Calendar.getInstance()
        calendar.time = issueDate
        calendar.add(Calendar.SECOND, 5)
        val expirationDate = calendar.time

        val jwt = Jwts.builder()
            .setId(JWTId.randomUUID().uuidString())
            .setIssuer("server")
            .setSubject(userId.uuidString())
            .setIssuedAt(issueDate)
            .setExpiration(expirationDate)
            .claim("groupId", groupId.uuidString())
            .claim("admin", true)
            .signWith(serverKeyPair.privateKey.signingKey())
            .compact()

        val membership = Membership(
            userId,
            groupId,
            PublicKey(0),
            true,
            serverSignedMembershipCertificate = ""
        )
        cryptoManager.validateServerSignedMembershipCertificate(jwt,membership,serverKeyPair.publicKey)
    }

    @ExperimentalStdlibApi
    private fun testValidateMembershipCertificateInvalidMembership() {
        val cryptoManager = CryptoManager(null)
        val keyPair = cryptoManager.generateSigningKeyPair()
        val testUser = TestUser(userId, keyPair.privateKey, keyPair.publicKey, null)

        val fakeId = UUID.fromString("A621E1F8-C36C-495A-93FC-0C247A3E6E5F")

        val certificateInvalidGroupId = cryptoManager.createUserSignedMembershipCertificate(userId, fakeId, true, userId, testUser)
        val certificateInvalidUserId = cryptoManager.createUserSignedMembershipCertificate(fakeId, groupId, true, fakeId, testUser)
        val certificateInvalidAdminFlag = cryptoManager.createUserSignedMembershipCertificate(userId, groupId, false, userId, testUser)

        val membership = Membership(
            userId,
            groupId,
            testUser.publicSigningKey,
            true,
            serverSignedMembershipCertificate = ""
        )

        try {
            cryptoManager.validateUserSignedMembershipCertificate(certificateInvalidGroupId, membership, testUser)
            throw Exception("Test failed")
        } catch(e: IncorrectClaimException) {}

        try {
            cryptoManager.validateUserSignedMembershipCertificate(certificateInvalidUserId, membership, testUser)
            throw Exception("Test failed")
        } catch(e: IncorrectClaimException) {}

        try {
            cryptoManager.validateUserSignedMembershipCertificate(certificateInvalidAdminFlag, membership, testUser)
            throw Exception("Test failed")
        } catch(e: IncorrectClaimException) {}
    }

    @ExperimentalStdlibApi
    private fun testValidateExpiredCertificate() {
        val cryptoManager = CryptoManager(null)
        val keyPair = cryptoManager.generateSigningKeyPair()
        val testUser = TestUser(userId, keyPair.privateKey, keyPair.publicKey, null)

        val issuedAtCalendar = Calendar.getInstance()
        issuedAtCalendar.time = Date()
        issuedAtCalendar.add(Calendar.SECOND, -20)
        val issueDate = issuedAtCalendar.time

        val calendar = Calendar.getInstance()
        calendar.time = issueDate
        calendar.add(Calendar.SECOND, -10)
        val expirationDate = calendar.time

        val jwt = Jwts.builder()
            .setId(JWTId.randomUUID().uuidString())
            .setIssuer(userId.uuidString())
            .setSubject(userId.uuidString())
            .setIssuedAt(issueDate)
            .setExpiration(expirationDate)
            .claim("groupId", groupId.uuidString())
            .claim("admin", true)
            .signWith(keyPair.privateKey.signingKey())
            .compact()

        val membership = Membership(
            userId,
            groupId,
            testUser.publicSigningKey,
            true,
            serverSignedMembershipCertificate = ""
        )

        try {
            cryptoManager.validateUserSignedMembershipCertificate(jwt, membership, testUser)
            throw Exception("Test failed")
        } catch (e: ExpiredJwtException) {}
    }

    @ExperimentalStdlibApi
    private fun testValidateCertificateIssuedInFuture() {
        val cryptoManager = CryptoManager(null)
        val keyPair = cryptoManager.generateSigningKeyPair()
        val testUser = TestUser(userId, keyPair.privateKey, keyPair.publicKey, null)

        val issuedAtCalendar = Calendar.getInstance()
        issuedAtCalendar.time = Date()
        issuedAtCalendar.add(Calendar.SECOND, 60)
        val issueDate = issuedAtCalendar.time

        val calendar = Calendar.getInstance()
        calendar.time = issueDate
        calendar.add(Calendar.SECOND, 3600)
        val expirationDate = calendar.time

        val jwt = Jwts.builder()
            .setId(JWTId.randomUUID().uuidString())
            .setIssuer(userId.uuidString())
            .setSubject(userId.uuidString())
            .setIssuedAt(issueDate)
            .setExpiration(expirationDate)
            .claim("groupId", groupId.uuidString())
            .claim("admin", true)
            .signWith(keyPair.privateKey.signingKey())
            .compact()

        val membership = Membership(
            userId,
            groupId,
            testUser.publicSigningKey,
            true,
            serverSignedMembershipCertificate = ""
        )

        try {
            cryptoManager.validateUserSignedMembershipCertificate(jwt, membership, testUser)
            throw Exception("Test failed")
        } catch (e: PrematureJwtException) {}
    }

    @ExperimentalStdlibApi
    private fun testValidateCertificateInvalidSignature() {
        val cryptoManager = CryptoManager(null)
        val keyPair = cryptoManager.generateSigningKeyPair()
        val testUser = TestUser(userId, keyPair.privateKey, keyPair.publicKey, null)

        val jwt = cryptoManager.createUserSignedMembershipCertificate(userId, groupId, true, userId, testUser)

        val fakeKeyPair = cryptoManager.generateSigningKeyPair()
        val fakeTestUser = TestUser(userId, fakeKeyPair.privateKey, fakeKeyPair.publicKey, null)

        val membership = Membership(
            userId,
            groupId,
            testUser.publicSigningKey,
            true,
            serverSignedMembershipCertificate = ""
        )

        try {
            cryptoManager.validateUserSignedMembershipCertificate(jwt, membership, fakeTestUser)
            throw Exception("Test failed")
        } catch (e: SignatureException) { }
    }

    @ExperimentalStdlibApi
    private suspend fun testInitializeConversation() {
        val cryptoManager = CryptoManager(TestCryptoStore())
        val keyPair = cryptoManager.generateSigningKeyPair()
        val testUser = TestUser(userId, keyPair.privateKey, keyPair.publicKey, null)

        val publicKeyMaterial = cryptoManager.generateHandshakeKeyMaterial(testUser, testUser.publicSigningKey)

        // Publish public key material...

        val keyPairBob = cryptoManager.generateSigningKeyPair()
        val bob = TestUser(UserId.randomUUID(), keyPairBob.privateKey, keyPairBob.publicKey, null)
        val bobsCryptoManager = CryptoManager(TestCryptoStore())
        bobsCryptoManager.generateHandshakeKeyMaterial(bob, bob.publicSigningKey)

        // Bob gets prekey bundle and remote verification key from server

        val conversationId = ConversationId.randomUUID()

        if (bobsCryptoManager.conversationInitialized(userId, conversationId)) {
            throw Exception("Test failed")
        }

        val invitation = bobsCryptoManager.initConversation(userId, conversationId, publicKeyMaterial.identityKey, publicKeyMaterial.signedPrekey, publicKeyMaterial.prekeySignature, publicKeyMaterial.oneTimePrekeys.first(), testUser.publicSigningKey)

        if (!bobsCryptoManager.conversationInitialized(userId, conversationId)) {
            throw Exception("Test failed")
        }

        // Invitation is transmitted ...

        cryptoManager.processConversationInvitation(invitation, bob.userId, conversationId)

        val firstMessagePayload = "Hello!".encodeToByteArray()
        val firstMessage = bobsCryptoManager.encrypt(firstMessagePayload, userId, conversationId)

        val plaintextData = cryptoManager.decrypt(firstMessage, bob.userId, conversationId)

        if (!firstMessagePayload.contentEquals(plaintextData)) {
            throw Exception("Test failed")
        }
    }

    @ExperimentalStdlibApi
    private fun testSymmetricEncryptionFixKey() {
        val cryptoManager = CryptoManager(null)
        val secretKey = cryptoManager.generateGroupKey()

        val plaintext = "Plaintext".encodeToByteArray()
        val ciphertext = cryptoManager.encrypt(plaintext, secretKey)

        val decrypted = cryptoManager.decrypt(ciphertext, secretKey)

        if (!decrypted.contentEquals(plaintext)) {
            throw Exception("Test failed")
        }
    }

    @ExperimentalStdlibApi
    private fun testSymmetricEncryptionGeneratedKey() {
        val cryptoManager = CryptoManager(null)

        val plaintext = "Plaintext".encodeToByteArray()
        val result = cryptoManager.encrypt(plaintext)

        val decrypted = cryptoManager.decrypt(result.first, result.second)

        if (!decrypted.contentEquals(plaintext)) {
            throw Exception("Test failed")
        }
    }

    private fun testUserPublicKeysComparison() {
        val userPublicKeys1 = UserPublicKeys(ByteArray(32), ByteArray(32), ByteArray(32), ByteArray(32), listOf(ByteArray(32)))
        val userPublicKeys2 = UserPublicKeys(ByteArray(32), ByteArray(32), ByteArray(32), ByteArray(32), listOf(ByteArray(32)))

        if (userPublicKeys1 != userPublicKeys2) {
            throw Exception("Test failed")
        }
    }

    @ExperimentalStdlibApi
    private fun testAuthHeader() {
        val cryptoManager = CryptoManager(null)
        val keyPair = cryptoManager.generateSigningKeyPair()
        val userId = UserId.randomUUID()
        val authHeader = cryptoManager.generateAuthHeader(keyPair.privateKey, userId)

        cryptoManager.verify(authHeader, userId, keyPair.publicKey)
    }
}

class TestUser(
    override val userId: UserId,
    override val privateSigningKey: PrivateKey,
    override var publicSigningKey: PublicKey,
    override var publicName: String?
) : UserType, Signer

class TestCryptoStore: CryptoStore {
    var identityKeyPair: KeyPair? = null
    var prekeyPair: KeyPair? = null
    var oneTimePrekeys: HashMap<PublicKey, PrivateKey> = HashMap()

    override suspend fun saveIdentityKeyPair(keyPair: KeyPair) {
        identityKeyPair = keyPair
    }

    override suspend fun savePrekeyPair(keyPair: KeyPair, signature: Signature) {
        prekeyPair = keyPair
    }

    override suspend fun saveOneTimePrekeyPairs(keyPairs: List<KeyPair>) {
        for (keyPair in keyPairs) {
            oneTimePrekeys[keyPair.publicKey] = keyPair.privateKey
        }
    }

    override suspend fun loadIdentityKeyPair(): KeyPair = identityKeyPair!!

    override suspend fun loadPrekeyPair(): KeyPair = prekeyPair!!

    override suspend fun loadPrekeySignature(): Signature {
        throw Exception("Not implemented")
    }

    override suspend fun loadPrivateOneTimePrekey(publicKey: PublicKey): PrivateKey = oneTimePrekeys[publicKey]!!

    override suspend fun deleteOneTimePrekeyPair(publicKey: PublicKey) {
    }

    override suspend fun saveConversationState(conversationState: ConversationState) {
    }

    override suspend fun loadConversationState(
        userId: UserId,
        conversationId: ConversationId
    ): ConversationState? {
        throw Exception("Not implemented")
    }

    override suspend fun loadConversationStates(): List<ConversationState> {
        throw Exception("Not implemented")
    }

}