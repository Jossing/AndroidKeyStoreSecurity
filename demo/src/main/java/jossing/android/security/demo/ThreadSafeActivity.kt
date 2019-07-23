package jossing.android.security.demo

import android.os.Bundle
import android.util.Base64
import android.util.Log
import androidx.appcompat.app.AppCompatActivity
import jossing.android.security.SecureCrypto
import kotlinx.android.synthetic.main.activity_thread_safe.*

/**
 *
 *
 * Date: 2019-07-23
 *
 * @author jossing
 */
class ThreadSafeActivity : AppCompatActivity() {

    companion object {

        private const val LOG_TAG = "ThreadSafeActivity"
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_thread_safe)
        btnStart.setOnClickListener { test() }
    }

    private fun test() {
        val content = arrayListOf(
            "12345", "67890", "qwert", "yuiop", "asdfg", "hjkl;", "zxcvb", "nm,./"
        )
        val encrypted = ArrayList<String>(content)
        val encrypt: (Int) -> Unit = { index ->
            SecureCrypto.encrypt(content[index].toByteArray()).also {
                encrypted[index] = if (it == null) "null" else {
                    Base64.encodeToString(it, Base64.NO_WRAP)
                }
            }
        }
        val encryptThreads = Array(content.size) { index ->
            Thread {
                encrypt(index)
            }.apply {
                name = "Test thread#$index"
            }
        }
        val decrypted = ArrayList<String>(content)
        val decrypt: (Int) -> Unit = { index ->
            SecureCrypto.decrypt(Base64.decode(encrypted[index], Base64.NO_WRAP)).also {
                decrypted[index] = if (it == null) "null" else String(it)
            }
        }
        val decryptThreads = Array(encrypted.size) { index ->
            Thread {
                decrypt(index)
            }.apply {
                name = "Test thread#$index"
            }
        }

        encryptThreads.forEach { it.start() }
        encrypted.forEach { Log.w(LOG_TAG, "加密 -> $it") }

        btnStart.postDelayed( { decryptThreads.forEach { it.start() } }, 1000)
        btnStart.postDelayed( { decrypted.forEach { Log.w(LOG_TAG, "解密 -> $it") } }, 1500)


    }
}