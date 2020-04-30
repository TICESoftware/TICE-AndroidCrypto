package com.ticeapp.ticeandroidcrypto

class Membership(
    val userId: UserId,
    val groupId: GroupId,
    val publicSigningKey: PublicKey,
    val admin: Boolean,
    val selfSignedMembershipCertificate: Certificate? = null,
    val serverSignedMembershipCertificate: Certificate,
    val adminSignedMembershipCertificate: Certificate? = null
)