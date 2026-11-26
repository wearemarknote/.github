package md.marknote.fixture

import java.security.MessageDigest
import javax.crypto.Cipher
import javax.crypto.Mac

// Cipher.getInstance("AES/CBC/PKCS5Padding") in a comment must not count.
object Vault {
    fun seal(key: ByteArray, plaintext: ByteArray): ByteArray {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        return cipher.doFinal(plaintext)
    }

    fun mac(key: ByteArray, message: ByteArray): ByteArray =
        Mac.getInstance("HmacSHA256").doFinal(message)

    fun challenge(verifier: ByteArray): ByteArray =
        MessageDigest.getInstance("SHA-256").digest(verifier)
}
