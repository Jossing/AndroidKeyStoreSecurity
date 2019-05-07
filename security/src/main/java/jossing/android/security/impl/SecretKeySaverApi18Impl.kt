package jossing.android.security.impl

import android.os.Build
import android.security.KeyPairGeneratorSpec
import android.util.Log
import androidx.annotation.RequiresApi
import jossing.android.security.AbstractSecretKeySaver
import jossing.android.security.SecureCryptoConfig.appContext
import jossing.android.security.SecureCryptoConfig.log
import java.io.*
import java.math.BigInteger
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.PublicKey
import java.security.spec.RSAKeyGenParameterSpec
import java.util.*
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.security.auth.x500.X500Principal

/**
 * 适用于 API18 ~ API23 的安全密钥安保员。
 *
 * 使用 KeyGenerator 配合 SecureRandom 生成随机 AES 密钥对外，
 * 再使用 AndroidKeyStore 生成的 RSA 密钥对保障 AES 密钥的安全。
 *
 * @author jossing
 * @date 2019/4/16
 */
@RequiresApi(Build.VERSION_CODES.JELLY_BEAN_MR2)
class SecretKeySaverApi18Impl : AbstractSecretKeySaver() {

    companion object {

        private const val LOG_TAG = "SecretKeySaverApi18Impl"

        /**
         * 安全密钥保存目录
         */
        private val dir get() = File(appContext.filesDir, "secret")

        /**
         * 安全密钥文件名
         */
        private val NAME by lazy { "secret_key" }

        /**
         * RSA 密码算法
         */
        private val RSA_TRANSFORMATION by lazy { "RSA/ECB/PKCS1Padding" }
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

    /**
     * 检查别名为 [alias] 的密钥是否存在
     *
     * @return 如果没有已有的合法密钥，返回 null
     */
    private fun checkSecretKey(alias: String): SecretKey? = synchronized(lockTouchSecretKey) {
        log { Log.d(LOG_TAG, "checkSecretKey -> 检查安全密钥是否存在") }
        val containsAlias = keyStore.containsAlias(alias)
        if (!containsAlias) {
            return null
        }
        // 检查 AndroidKeyStore 中是否存在 RSA 密钥对
        val privateKey: PrivateKey
        try {
            privateKey = keyStore.getKey(alias, null) as? PrivateKey ?: return null
            keyStore.getCertificate(alias)?.publicKey ?: return null
        } catch (tr: Throwable) {
            kotlin.runCatching {
                keyStore.deleteEntry(alias)
            }
            log { Log.w(LOG_TAG, "checkSecretKey -> AndroidKeyStore 中不存在有效的 RSA 密钥对", tr) }
            return null
        }
        // 检查本地是否已有合法的 AES 密钥
        val secretKey: SecretKey
        val secretKeyFile = File(dir, NAME)
        log { Log.d(LOG_TAG, "checkSecretKey -> 安全密钥文件: (${secretKeyFile.length()})$secretKeyFile") }
        try {
            if (!secretKeyFile.exists()) {
                log { Log.w(LOG_TAG, "checkSecretKey -> 密钥文件不存在") }
                return null
            }
            val key = FileInputStream(secretKeyFile).buffered().use {
                it.readBytes()
            }
            secretKey = rsaDecryptSecretKey(key, privateKey)
        } catch (tr: Throwable) {
            secretKeyFile.delete()
            log { Log.w(LOG_TAG, "checkSecretKey -> 存储到本地的 AES 密钥非法", tr) }
            return null
        }
        log { Log.d(LOG_TAG, "checkSecretKey -> 安全密钥存在") }
        // 通过了层层校验，确实已存在能用的 AES 密钥
        return secretKey
    }

    /**
     * 生成新的 AES 密钥
     */
    private fun refreshSecretKey(alias: String): SecretKey = synchronized(lockTouchSecretKey) {
        log { Log.d(LOG_TAG, "refreshSecretKey -> 准备生成新的安全密钥") }
        val secretKeyFile = File(dir, NAME)
        log { Log.d(LOG_TAG, "refreshSecretKey -> 安全密钥文件: (${secretKeyFile.length()})$secretKeyFile") }
        // 原有的 RSA 密钥对，和 AES 密钥直接删除
        log { Log.d(LOG_TAG, "refreshSecretKey -> 删除已有的安全密钥") }
        kotlin.runCatching {
            secretKeyFile.delete()
            keyStore.deleteEntry(alias)
        }
        log { Log.d(LOG_TAG, "refreshSecretKey -> 生成新的 RSA 密钥对") }
        // 使用 AndroidKeyStore 创建新的 RSA 密钥对
        val calendar = Calendar.getInstance()
        val keyPairGeneratorSpec = KeyPairGeneratorSpec.Builder(appContext)
                .setAlias(alias)
                .setSubject(X500Principal("CN = SecretKeySaver"))
                .setSerialNumber(BigInteger.valueOf(System.currentTimeMillis()))
                .setStartDate(calendar.time)
                .setEndDate(calendar.apply { add(Calendar.YEAR, 99) }.time)
                .apply {
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.KITKAT) {
                        setAlgorithmParameterSpec(RSAKeyGenParameterSpec(2048, RSAKeyGenParameterSpec.F4))
                    }
                }
                .build()
        val keyPairGenerator = KeyPairGenerator.getInstance("RSA", ANDROID_KEY_STORE)
        keyPairGenerator.initialize(keyPairGeneratorSpec, strongSecureRandom)
        val keyPair = keyPairGenerator.genKeyPair()
        log { Log.d(LOG_TAG, "refreshSecretKey -> 生成新的 AES 密钥") }
        // 使用 SecureRandom 生成 AES 密钥
        val keyGenerator = KeyGenerator.getInstance("AES")
        keyGenerator.init(256, strongSecureRandom)
        val secretKey = keyGenerator.generateKey()
        log { Log.d(LOG_TAG, "refreshSecretKey -> 加密 AES 密钥后保存本地") }
        // RSA 加密 AES 密钥，然后保存到本地
        val encrypted = rsaEncryptSecretKey(secretKey, keyPair.public)
        secretKeyFile.parentFile?.mkdirs()
        FileOutputStream(secretKeyFile).buffered().use {
            it.write(encrypted)
        }
        log { Log.d(LOG_TAG, "refreshSecretKey -> 生成新的安全密钥完成") }
        // 返回新鲜出炉的密钥
        return secretKey
    }

    /**
     * RSA 加密 AES 密钥
     */
    @Throws(Throwable::class)
    private fun rsaEncryptSecretKey(secretKey: SecretKey, publicKey: PublicKey): ByteArray {
        val cipher = Cipher.getInstance(RSA_TRANSFORMATION)
        cipher.init(Cipher.WRAP_MODE, publicKey, strongSecureRandom)
        return cipher.wrap(secretKey)
    }

    /**
     * RSA 解密 AES 密钥
     */
    @Throws(Throwable::class)
    private fun rsaDecryptSecretKey(secretKey: ByteArray, privateKey: PrivateKey): SecretKey {
        val cipher = Cipher.getInstance(RSA_TRANSFORMATION)
        cipher.init(Cipher.UNWRAP_MODE, privateKey, strongSecureRandom)
        return cipher.unwrap(secretKey, "AES", Cipher.SECRET_KEY) as SecretKey
    }
}