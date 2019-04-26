package jossing.android.security.impl

import android.os.Build
import android.util.Log
import jossing.android.security.AbstractSecretKeySaver
import jossing.android.security.SecureCryptoConfig.log
import jossing.android.security.SecureCryptoInterface
import java.lang.IllegalArgumentException
import java.nio.ByteBuffer
import java.security.SecureRandom
import java.security.spec.AlgorithmParameterSpec
import java.util.*
import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.IvParameterSpec

/**
 * 利用 AndroidKeyStore 实现的 AES 安全加密工具。
 *
 * 加密时随机生成偏移量，对于 API21+，使用 GCM 模式，否则使用 CBC 模式。
 *
 * @author jossing
 * @date 2019/4/15
 */
internal class AndroidKeyStoreSecureCryptoImpl : SecureCryptoInterface, AbstractSecretKeySaver() {

    companion object {

        private const val LOG_TAG = "AndroidKeyStoreCrypto"

        private const val SECRET_KEY_ALIAS = "SecureCryptoKey"

        private val isOverApi21 = Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP

        /**
         * AES 密码算法。API21+ 使用 GCM 模式，否则使用 CBC 模式
         */
        private val AES_TRANSFORMATION by lazy { if (isOverApi21)
            "AES/GCM/NoPadding" else "AES/CBC/PKCS7Padding"
        }

        /**
         * AES 加密向量。GCM 模式只支持 12 字节的向量，CBC 模式建议使用 16 字节的向量
         */
        private val IV_LENGTH by lazy { if (isOverApi21) 12 else 16 }
    }

    /**
     * 密钥安保策略
     */
    private val secretKeySaver by lazy {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            SecretKeySaverApi23Impl()
        } else {
            SecretKeySaverApi18Impl()
        }
    }

    /**
     * 创建加密向量参数
     *
     * @param gcmTagSize 用于 GCM 模式的认证标签大小。默认为最大的 128 位
     */
    private fun genIvParameterSpec(gcmTagSize: Int = 128, ivBytes: ByteArray): AlgorithmParameterSpec {
        return if (isOverApi21) {
            GCMParameterSpec(gcmTagSize, ivBytes)
        } else {
            IvParameterSpec(ivBytes)
        }
    }

    /**
     * 获取 [cipher] 的偏移量参数
     */
    private fun getIvParameterSpec(cipher: Cipher): AlgorithmParameterSpec? {
        return kotlin.runCatching { if (isOverApi21) {
            cipher.parameters.getParameterSpec(GCMParameterSpec::class.java)
        } else {
            cipher.parameters.getParameterSpec(IvParameterSpec::class.java)
        }}.getOrNull()
    }

    override fun encrypt(content: ByteArray): ByteArray {
        // 构建 Cipher
        val secretKey = getSecretKey(SECRET_KEY_ALIAS)
        val cipher = Cipher.getInstance(AES_TRANSFORMATION)
        val cipherSecureRandom = SecureRandom(SecureRandom.getSeed(256))
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, cipherSecureRandom)
        // 计算认证标签大小
        val gcmTagSize = getIvParameterSpec(cipher).run {
            if (this == null) {
                log { Log.d(LOG_TAG, "encrypt -> 手动导入向量") }
                // 使用强伪随机源生成随机向量
                val ivSecureRandom = SecureRandom(SecureRandom.getSeed(256))
                val ivBytes = ByteArray(IV_LENGTH)
                ivSecureRandom.nextBytes(ivBytes)
                val ivParameterSpec = genIvParameterSpec(ivBytes = ivBytes)
                cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivParameterSpec, cipherSecureRandom)
                ivParameterSpec
            } else {
                log { Log.d(LOG_TAG, "encrypt -> 自动生成向量") }
                this
            }
        }.run { if (isOverApi21) (this as GCMParameterSpec).tLen else 0 }
        log { Log.d(LOG_TAG, "encrypt -> 用于 GCM 模式的认证标签大小：$gcmTagSize") }
        // 加密
        val cipherText = cipher.doFinal(content)
        // 拼装密文
        return CipherMessage.wrap(gcmTagSize, cipher.iv, cipherText)
    }

    override fun decrypt(cipherText: ByteArray): ByteArray {
        val secureRandom = SecureRandom(SecureRandom.getSeed(256))
        val cipherMessage = CipherMessage.unwrap(cipherText)
        val secretKey = getSecretKey(SECRET_KEY_ALIAS)
        val cipher = Cipher.getInstance(AES_TRANSFORMATION)
        val ivParameterSpec = genIvParameterSpec(cipherMessage.tagSize, cipherMessage.ivBytes)
        cipher.init(Cipher.DECRYPT_MODE, secretKey, ivParameterSpec, secureRandom)
        return cipher.doFinal(cipherMessage.cipherText)
    }

    override fun getSecretKey(alias: String): SecretKey {
        return secretKeySaver.getSecretKey(alias)
    }

    override fun forceUpdate(alias: String) {
        secretKeySaver.forceUpdate(alias)
    }

    /**
     * 密文包装器。将明文的加密结果和向量拼装成一条消息
     *
     * @param tagSize GCM 认证标签大小。非 GCM 模式传 0
     * @param ivBytes 向量
     * @param cipherText 密文
     */
    private data class CipherMessage(val tagSize: Int, val ivBytes: ByteArray, val cipherText: ByteArray) {

        companion object {

            /**
             * 包装密文
             *
             * @param tagSize GCM 认证标签大小。非 GCM 模式传 0
             * @param ivBytes 向量
             * @param cipherText 密文
             * @return 消息
             */
            internal fun wrap(tagSize: Int, ivBytes: ByteArray, cipherText: ByteArray): ByteArray {
                val byteBuffer = ByteBuffer.allocate(1 + ivBytes.size + 4 + cipherText.size)
                byteBuffer.put(ivBytes.size.toByte())
                byteBuffer.put(ivBytes)
                byteBuffer.putInt(tagSize)
                byteBuffer.put(cipherText)
                val cipherMessage = byteBuffer.array()
                Arrays.fill(ivBytes, 0.toByte())
                Arrays.fill(cipherText, 0.toByte())
                return cipherMessage
            }

            /**
             * 解包消息
             *
             * @param cipherMessage 消息
             * @return 密文和用于解密的向量
             */
            internal fun unwrap(cipherMessage: ByteArray): CipherMessage {
                val cipherMessageBuffer = ByteBuffer.wrap(cipherMessage)
                val ivLength = cipherMessageBuffer.get().toInt()
                // 必须首先检查向量长度，避免攻击者将长度更改为超大数值爆破内存堆栈
                if (ivLength != IV_LENGTH) {
                    throw IllegalArgumentException("CipherMessage unwrap error: invalid iv length: $ivLength.")
                }
                val ivBytes = ByteArray(ivLength)
                cipherMessageBuffer.get(ivBytes)
                val tagSize = cipherMessageBuffer.int
                val cipherText = ByteArray(cipherMessageBuffer.remaining())
                cipherMessageBuffer.get(cipherText)
                return CipherMessage(tagSize, ivBytes, cipherText)
            }
        }

        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (javaClass != other?.javaClass) return false

            other as CipherMessage

            if (tagSize != other.tagSize) return false
            if (!ivBytes.contentEquals(other.ivBytes)) return false
            if (!cipherText.contentEquals(other.cipherText)) return false

            return true
        }

        override fun hashCode(): Int {
            var result = tagSize
            result = 31 * result + ivBytes.contentHashCode()
            result = 31 * result + cipherText.contentHashCode()
            return result
        }
    }
}