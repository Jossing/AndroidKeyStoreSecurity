package jossing.android.security

import jossing.android.security.SecureCryptoConfig.log
import jossing.android.security.impl.AndroidKeyStoreSecureCryptoImpl
import java.security.Key


/**
 * 安全加密工具
 *
 * @author jossing
 * @date 2019/4/15
 */
object SecureCrypto {

    /**
     * 安全加密的实现
     */
    internal var secureCryptoImpl: SecureCryptoInterface = AndroidKeyStoreSecureCryptoImpl()

    /**
     * 加解密失败的默认回调
     */
    private val defaultOnFailed: (Throwable) -> Unit = {
        log { it.printStackTrace() }
    }

    /**
     * 加密
     *
     * @param content 明文
     * @param onFailed 加密异常时调用的函数。可以自行处理异常，自定义加密异常时的返回值
     * @return 加密成功产生密文
     */
    @JvmStatic
    @JvmOverloads
    fun encrypt(content: ByteArray?, onFailed: (Throwable) -> Unit = defaultOnFailed): ByteArray? {
        if (content == null) {
            onFailed(NullPointerException("content is null!"))
            return null
        }
        return try {
            secureCryptoImpl.encrypt(content)
        } catch (tr: Throwable) {
            onFailed(tr)
            null
        }
    }

    /**
     * 解密
     *
     * @param cipherText 密文
     * @param onFailed 解密异常时调用的函数。可以自行处理异常，自定义解密异常时的返回值
     * @return 解密成功输出明文
     */
    @JvmStatic
    @JvmOverloads
    fun decrypt(cipherText: ByteArray?, onFailed: (Throwable) -> Unit = defaultOnFailed): ByteArray? {
        if (cipherText == null) {
            onFailed(NullPointerException("cipherText is null!"))
            return null
        }
        return try {
            secureCryptoImpl.decrypt(cipherText)
        } catch (tr: Throwable) {
            onFailed(tr)
            null
        }
    }

    /**
     * 加密密钥
     *
     * @param key 密钥
     * @param onFailed 加密异常时调用的函数。可以自行处理异常，自定义加密异常时的返回值
     * @return 经过加密的密钥
     */
    @JvmStatic
    @JvmOverloads
    fun wrap(key: Key?, onFailed: (Throwable) -> Unit = defaultOnFailed): ByteArray? {
        if (key == null) {
            onFailed(NullPointerException("key is null!"))
            return null
        }
        return try {
            secureCryptoImpl.wrap(key)
        } catch (tr: Throwable) {
            onFailed(tr)
            null
        }
    }

    /**
     * 解密密钥
     *
     * @param keyBytes 经过加密的密钥
     * @param wrappedKeyAlgorithm 密钥算法名称
     * @param wrappedKeyType 密钥类型
     * @param onFailed 解密异常时调用的函数。可以自行处理异常，自定义解密异常时的返回值
     * @return 密钥
     */
    @JvmStatic
    @JvmOverloads
    fun <T : Key> unwrap(keyBytes: ByteArray?, wrappedKeyAlgorithm: String?, wrappedKeyType: Class<T>, onFailed: (Throwable) -> Unit = defaultOnFailed): T? {
        if (keyBytes == null) {
            onFailed(NullPointerException("keyBytes is null!"))
            return null
        }
        if (wrappedKeyAlgorithm == null) {
            onFailed(NullPointerException("wrappedKeyAlgorithm is null!"))
            return null
        }
        return try {
            secureCryptoImpl.unwrap(keyBytes, wrappedKeyAlgorithm, wrappedKeyType)
        } catch (tr: Throwable) {
            onFailed(tr)
            null
        }
    }
}