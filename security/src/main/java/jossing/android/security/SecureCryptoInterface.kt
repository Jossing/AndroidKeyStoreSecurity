package jossing.android.security

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
}