package com.ticeapp.ticeandroidcrypto

data class ConversationInvitation(val identityKey: PublicKey, val ephemeralKey: PublicKey, val usedOneTimePrekey: PublicKey?)