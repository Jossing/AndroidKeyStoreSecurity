package jossing.android.security

import java.security.KeyStore
import java.security.SecureRandom
import javax.crypto.SecretKey

/**
 * 安全密钥安保员抽象
 *
 * @author jossing
 * @date 2019/4/16
 */
abstract class AbstractSecretKeySaver {

    companion object {

        internal val ANDROID_KEY_STORE by lazy { "AndroidKeyStore" }
    }

    protected val keyStore get() = KeyStore.getInstance(ANDROID_KEY_STORE).apply { load(null) }

    /**
     * 建议使用的强伪随机源
     */
    protected val strongSecureRandom by lazy { runCatching {
        SecureRandom.getInstance("SHA1PRNG")
    }.getOrDefault(SecureRandom(SecureRandom.getSeed(256))) }

    /**
     * 获取安全密钥
     */
    abstract fun getSecretKey(alias: String): SecretKey

    /**
     * 强制更新安全密钥
     */
    abstract fun forceUpdate(alias: String)
}