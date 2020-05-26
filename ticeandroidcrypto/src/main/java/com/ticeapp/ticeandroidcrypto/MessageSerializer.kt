package com.ticeapp.ticeandroidcrypto

import com.goterl.lazycode.lazysodium.utils.Key
import com.ticeapp.androiddoubleratchet.Header
import com.ticeapp.androiddoubleratchet.KeySerializer
import com.ticeapp.androiddoubleratchet.Message
import kotlinx.serialization.*
import kotlinx.serialization.builtins.ByteArraySerializer
import kotlinx.serialization.builtins.ListSerializer

class UnsignedByteSerializer: KSerializer<UByte> {
    override val descriptor: SerialDescriptor = PrimitiveDescriptor("UByte", PrimitiveKind.INT)
    override fun serialize(encoder: Encoder, value: UByte) = encoder.encodeInt(value.toInt())
    override fun deserialize(decoder: Decoder): UByte = decoder.decodeInt().toUByte()
    override fun patch(decoder: Decoder, old: UByte): UByte = deserialize(decoder)
}

object HeaderSerializer: KSerializer<Header> {
    @ImplicitReflectionSerializer
    override val descriptor: SerialDescriptor = SerialDescriptor("Header") {
        element<String>("publicKey")
        element<String>("numberOfMessagesInPreviousSendingChain")
        element<String>("messageNumber")
    }
    @ExperimentalUnsignedTypes
    @ImplicitReflectionSerializer
    override fun serialize(encoder: Encoder, value: Header) {
        val composite = encoder.beginStructure(descriptor)
        composite.encodeSerializableElement(descriptor, 0, ListSerializer(UnsignedByteSerializer()), value.publicKey.asBytes.toUByteArray().asList())
        composite.encodeIntElement(descriptor, 1, value.numberOfMessagesInPreviousSendingChain)
        composite.encodeIntElement(descriptor, 2, value.messageNumber)
        composite.endStructure(descriptor)
    }

    @ExperimentalUnsignedTypes
    @ImplicitReflectionSerializer
    override fun deserialize(decoder: Decoder): Header {
        val composite = decoder.beginStructure(descriptor)

        var publicKey: Key? = null
        var numberOfMessagesInPreviousSendingChain: Int? = null
        var messageNumber: Int? = null
        for (i in 0..2) {
            when(composite.decodeElementIndex(descriptor)) {
                0 -> publicKey = composite.decodeSerializableElement(descriptor, 0, ListSerializer(UnsignedByteSerializer())).toUByteArray().asByteArray().cryptoKey()
                1 -> numberOfMessagesInPreviousSendingChain = composite.decodeIntElement(descriptor, 1)
                2 -> messageNumber = composite.decodeIntElement(descriptor, 2)
            }
        }

        composite.endStructure(descriptor)

        return Header(publicKey!!, numberOfMessagesInPreviousSendingChain!!, messageNumber!!)
    }
    @ExperimentalUnsignedTypes
    @ImplicitReflectionSerializer
    override fun patch(decoder: Decoder, old: Header): Header = deserialize(decoder)
}

object MessageSerializer: KSerializer<Message> {
    @ImplicitReflectionSerializer
    override val descriptor: SerialDescriptor = SerialDescriptor("Message") {
        element<String>("header")
        element<String>("cipher")
    }
    @ExperimentalUnsignedTypes
    @ImplicitReflectionSerializer
    override fun serialize(encoder: Encoder, value: Message) {
        val composite = encoder.beginStructure(descriptor)
        composite.encodeSerializableElement(descriptor, 0, HeaderSerializer, value.header)
        composite.encodeSerializableElement(descriptor, 1, ListSerializer(UnsignedByteSerializer()), value.cipher.toUByteArray().asList())
        composite.endStructure(descriptor)
    }

    @ExperimentalUnsignedTypes
    @ImplicitReflectionSerializer
    override fun deserialize(decoder: Decoder): Message {
        val composite = decoder.beginStructure(descriptor)

        var header: Header? = null
        var cipher: ByteArray? = null
        for (i in 0..2) {
            when(composite.decodeElementIndex(descriptor)) {
                0 -> header = composite.decodeSerializableElement(descriptor, 0, HeaderSerializer)
                1 -> cipher = composite.decodeSerializableElement(descriptor, 1, ListSerializer(UnsignedByteSerializer())).toUByteArray().asByteArray()
            }
        }

        composite.endStructure(descriptor)

        return Message(header!!, cipher!!)
    }
    @ExperimentalUnsignedTypes
    @ImplicitReflectionSerializer
    override fun patch(decoder: Decoder, old: Message): Message = deserialize(decoder)
}
