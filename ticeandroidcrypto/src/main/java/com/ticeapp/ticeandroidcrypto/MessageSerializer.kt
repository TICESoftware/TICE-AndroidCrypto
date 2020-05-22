package com.ticeapp.ticeandroidcrypto

import android.util.Base64
import com.goterl.lazycode.lazysodium.utils.Key
import com.ticeapp.androiddoubleratchet.Header
import com.ticeapp.androiddoubleratchet.KeySerializer
import com.ticeapp.androiddoubleratchet.Message
import kotlinx.serialization.*
import kotlinx.serialization.builtins.ByteArraySerializer

class Base64ByteArraySerializer: KSerializer<ByteArray> {
    override val descriptor: SerialDescriptor = PrimitiveDescriptor("Base64ByteArray", PrimitiveKind.STRING)
    override fun serialize(encoder: Encoder, value: ByteArray) = encoder.encodeString(Base64.encodeToString(value, Base64.NO_WRAP))
    override fun deserialize(decoder: Decoder): ByteArray = Base64.decode(decoder.decodeString(), Base64.NO_WRAP)
    override fun patch(decoder: Decoder, old: ByteArray): ByteArray = deserialize(decoder)
}

object HeaderSerializer: KSerializer<Header> {
    @ImplicitReflectionSerializer
    override val descriptor: SerialDescriptor = SerialDescriptor("Header") {
        element<String>("publicKey")
        element<String>("numberOfMessagesInPreviousSendingChain")
        element<String>("messageNumber")
    }
    @ImplicitReflectionSerializer
    override fun serialize(encoder: Encoder, value: Header) {
        val composite = encoder.beginStructure(descriptor)
        composite.encodeSerializableElement(descriptor, 0, KeySerializer(), value.publicKey)
        composite.encodeIntElement(descriptor, 1, value.numberOfMessagesInPreviousSendingChain)
        composite.encodeIntElement(descriptor, 2, value.messageNumber)
        composite.endStructure(descriptor)
    }

    @ImplicitReflectionSerializer
    override fun deserialize(decoder: Decoder): Header {
        val composite = decoder.beginStructure(descriptor)

        var publicKey: Key? = null
        var numberOfMessagesInPreviousSendingChain: Int? = null
        var messageNumber: Int? = null
        for (i in 0..2) {
            when(composite.decodeElementIndex(descriptor)) {
                0 -> publicKey = composite.decodeSerializableElement(descriptor, 0, KeySerializer())
                1 -> numberOfMessagesInPreviousSendingChain = composite.decodeIntElement(descriptor, 1)
                2 -> messageNumber = composite.decodeIntElement(descriptor, 2)
            }
        }

        composite.endStructure(descriptor)

        return Header(publicKey!!, numberOfMessagesInPreviousSendingChain!!, messageNumber!!)
    }
    @ImplicitReflectionSerializer
    override fun patch(decoder: Decoder, old: Header): Header = deserialize(decoder)
}

object MessageSerializer: KSerializer<Message> {
    @ImplicitReflectionSerializer
    override val descriptor: SerialDescriptor = SerialDescriptor("Message") {
        element<String>("header")
        element<String>("cipher")
    }
    @ImplicitReflectionSerializer
    override fun serialize(encoder: Encoder, value: Message) {
        val composite = encoder.beginStructure(descriptor)
        composite.encodeSerializableElement(descriptor, 0, HeaderSerializer, value.header)
        composite.encodeSerializableElement(descriptor, 1, Base64ByteArraySerializer(), value.cipher)
        composite.endStructure(descriptor)
    }

    @ImplicitReflectionSerializer
    override fun deserialize(decoder: Decoder): Message {
        val composite = decoder.beginStructure(descriptor)

        var header: Header? = null
        var cipher: ByteArray? = null
        for (i in 0..2) {
            when(composite.decodeElementIndex(descriptor)) {
                0 -> header = composite.decodeSerializableElement(descriptor, 0, HeaderSerializer)
                1 -> cipher = composite.decodeSerializableElement(descriptor, 1, Base64ByteArraySerializer())
            }
        }

        composite.endStructure(descriptor)

        return Message(header!!, cipher!!)
    }
    @ImplicitReflectionSerializer
    override fun patch(decoder: Decoder, old: Message): Message = deserialize(decoder)
}
