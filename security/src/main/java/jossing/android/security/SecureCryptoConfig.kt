package jossing.android.security

import android.content.Context
import jossing.android.security.impl.AndroidKeyStoreSecureCryptoImpl

/**
 * 安全加密工具配置入口
 *
 * @author jossing
 * @date 2019/4/16
 */
object SecureCryptoConfig {

    private lateinit var context: () -> Context

    internal val appContext: Context get() {
        return try {
            context()
        } catch (tr: UninitializedPropertyAccessException) {
            throw UninitializedPropertyAccessException("必须先调用 SecureCryptoConfig.setAppContext", tr)
        }
    }

    private var debugable = BuildConfig.DEBUG

    @JvmStatic
    fun setAppContext(context: () -> Context) {
        SecureCryptoConfig.context = { context().applicationContext }
    }

    /**
     * 是否允许输出 Debug 信息。默认为 [BuildConfig.DEBUG]
     */
    @JvmStatic
    fun setDebugable(debugable: Boolean): SecureCryptoConfig {
        SecureCryptoConfig.debugable = debugable
        return SecureCryptoConfig
    }

    internal fun log(log: () -> Unit) {
        if (debugable) {
            log()
        }
    }

    /**
     * 自定义安全加密实现类
     *
     * @param secureCryptoImpl 安全加密自定义实现。默认值：[AndroidKeyStoreSecureCryptoImpl]
     */
    @JvmStatic
    @JvmOverloads
    fun setSecureCryptoImpl(secureCryptoImpl: SecureCryptoInterface = AndroidKeyStoreSecureCryptoImpl()) {
        SecureCrypto.secureCryptoImpl = secureCryptoImpl
    }
}