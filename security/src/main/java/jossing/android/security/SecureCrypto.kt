package jossing.android.security

import jossing.android.security.SecureCryptoConfig.log
import jossing.android.security.impl.AndroidKeyStoreSecureCryptoImpl


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
}