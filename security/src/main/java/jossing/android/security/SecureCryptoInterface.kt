package jossing.android.security

import java.security.Key

/**
 * 抽象安全加密工具
 *
 * @author jossing
 * @date 2019/4/15
 */
interface SecureCryptoInterface {

    /**
     * 加密
     *
     * @param content 明文
     * @return 密文
     */
    @Throws(Throwable::class)
    fun encrypt(content: ByteArray): ByteArray

    /**
     * 解密
     *
     * @param cipherText 密文
     * @return 明文
     */
    @Throws(Throwable::class)
    fun decrypt(cipherText: ByteArray): ByteArray

    /**
     * 加密密钥
     *
     * @param key 密钥
     * @return 经过加密的密钥
     */
    @Throws(Throwable::class)
    fun wrap(key: Key): ByteArray

    /**
     * 解密密钥
     *
     * @param keyBytes 经过加密的密钥
     * @param wrappedKeyAlgorithm 密钥算法名称
     * @param wrappedKeyType 密钥类型
     * @return 密钥
     */
    @Throws(Throwable::class)
    fun <T : Key> unwrap(keyBytes: ByteArray, wrappedKeyAlgorithm: String, wrappedKeyType: Class<T>): T
}