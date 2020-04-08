package com.ticeapp.ticeandroidcryptoapp

import androidx.appcompat.app.AppCompatActivity
import android.os.Bundle
import com.ticeapp.ticeandroidcrypto.CryptoManager
import com.ticeapp.ticeandroidcrypto.JWTId
import com.ticeapp.ticeandroidcrypto.Signer
import com.ticeapp.ticeandroidcrypto.signingKey
import com.ticeapp.ticeandroidmodels.*
import io.jsonwebtoken.*
import io.jsonwebtoken.security.SignatureException
import java.util.*

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
        testUserSignedMembershipCertificate()
        testServerSignedMembershipCertificate()
        testValidateMembershipCertificateInvalidMembership()
        testValidateExpiredCertificate()
        testValidateCertificateIssuedInFuture()
        testValidateCertificateInvalidSignature()
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
            .setId(JWTId.randomUUID().toString())
            .setIssuer("server")
            .setSubject(userId.toString())
            .setIssuedAt(issueDate)
            .setExpiration(expirationDate)
            .claim("groupId", groupId.toString())
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
            .setId(JWTId.randomUUID().toString())
            .setIssuer(userId.toString())
            .setSubject(userId.toString())
            .setIssuedAt(issueDate)
            .setExpiration(expirationDate)
            .claim("groupId", groupId.toString())
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
            .setId(JWTId.randomUUID().toString())
            .setIssuer(userId.toString())
            .setSubject(userId.toString())
            .setIssuedAt(issueDate)
            .setExpiration(expirationDate)
            .claim("groupId", groupId.toString())
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
}

class TestUser(
    userId: UserId,
    override val privateSigningKey: PrivateKey,
    publicSigningKey: PublicKey,
    publicName: String?
) : User(userId, publicSigningKey, publicName), Signer