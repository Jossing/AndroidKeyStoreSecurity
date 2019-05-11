package jossing.android.security.impl

import android.annotation.TargetApi
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Log
import jossing.android.security.AbstractSecretKeySaver
import jossing.android.security.SecureCryptoConfig.log
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey

/**
 * 适用于 API23+ 的安全密钥安保员。
 *
 * 使用 AndroidKeyStore 原生方案实现 AES 密钥管理。
 *
 * @author jossing
 * @date 2019/4/16
 */
@TargetApi(Build.VERSION_CODES.M)
class SecretKeySaverApi23Impl : AbstractSecretKeySaver() {

    companion object {

        private const val LOG_TAG = "SecretKeySaverApi23Impl"
    }

    /**
     * 安全密钥操作的同步锁
     */
    private val lockTouchSecretKey = Any()

    override fun getSecretKey(alias: String): SecretKey {
        return checkSecretKey(alias) ?: refreshSecretKey(alias)
    }

    override fun forceUpdate(alias: String) {
        log { Log.d(LOG_TAG, "forceUpdate -> 准备强制更新密钥") }
        refreshSecretKey(alias)
    }

    private fun checkSecretKey(alias: String): SecretKey? = synchronized(lockTouchSecretKey) {
        log { Log.d(LOG_TAG, "checkSecretKey -> 检查安全密钥是否存在") }
        val containsAlias = keyStore.containsAlias(alias)
        if (!containsAlias) {
            return null
        }
        // 检查 AndroidKeyStore 中是否存在 AES 密钥
        val secretKey: SecretKey
        try {
            secretKey = keyStore.getKey(alias, null) as? SecretKey ?: return null
        } catch (tr: Throwable) {
            kotlin.runCatching {
                keyStore.deleteEntry(alias)
            }
            log { Log.w(LOG_TAG, "checkSecretKey -> AndroidKeyStore 中不存在有效的 AES 密钥", tr) }
            return null
        }
        log { Log.d(LOG_TAG, "checkSecretKey -> 安全密钥存在") }
        return secretKey
    }

    private fun refreshSecretKey(alias: String): SecretKey = synchronized(lockTouchSecretKey) {
        log { Log.d(LOG_TAG, "refreshSecretKey -> 准备生成新的安全密钥") }
        // 原有的 AES 密钥直接删除
        log { Log.d(LOG_TAG, "refreshSecretKey -> 删除已有的安全密钥") }
        kotlin.runCatching {
            keyStore.deleteEntry(alias)
        }
        log { Log.d(LOG_TAG, "refreshSecretKey -> 生成新的 AES 密钥") }
        // 使用 AndroidKeyStore 创建新的 RSA 密钥对
        val purposes = KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        val keyGenParameterSpec = KeyGenParameterSpec.Builder(alias, purposes)
                .setKeySize(256)
                .setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA512)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM, KeyProperties.BLOCK_MODE_CBC)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7,
                        KeyProperties.ENCRYPTION_PADDING_NONE)
                .setRandomizedEncryptionRequired(true)
                .build()
        val keyGenerator = KeyGenerator.getInstance("AES", ANDROID_KEY_STORE)
        keyGenerator.init(keyGenParameterSpec, strongSecureRandom)
        log { Log.d(LOG_TAG, "refreshSecretKey -> 生成新的安全密钥完成") }
        return keyGenerator.generateKey()
    }
}