package io.github.acapitow.vault.crypto

fun String.hex(): ByteArray = chunked(2).map { it.toInt(16).toByte() }.toByteArray()

fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }
