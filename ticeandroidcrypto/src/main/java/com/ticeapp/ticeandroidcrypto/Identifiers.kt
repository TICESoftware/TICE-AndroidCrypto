package com.ticeapp.ticeandroidcrypto

import java.util.*

typealias ConversationId = UUID
typealias UserId = UUID
typealias GroupId = UUID

fun UUID.uuidString(): String = toString().toUpperCase(Locale.ROOT)