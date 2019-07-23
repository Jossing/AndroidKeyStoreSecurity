package jossing.android.security.demo

import android.content.Intent
import androidx.appcompat.app.AppCompatActivity
import android.os.Bundle
import android.text.Editable
import android.text.TextWatcher
import android.util.Base64
import android.view.Menu
import android.view.MenuItem
import android.view.View
import android.widget.Toast
import jossing.android.security.SecureCrypto
import jossing.android.security.SecureCryptoConfig
import kotlinx.android.synthetic.main.activity_main.*
import java.security.SecureRandom
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey

class MainActivity : AppCompatActivity() {

    /**
     * 模式切换。0：普通加解密；1：密文包装解包
     */
    private var mode: Int = 0

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        applicationContext.also {
            SecureCryptoConfig.setAppContext(it)
            SecureCryptoConfig.setDebugable(true)
        }

        etContent.addTextChangedListener(object : SimpleTextWatcher() {
            override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) {
                btnEncrypt.isEnabled = s?.toString()?.trim()?.isNotEmpty() ?: false
            }
        })
        tvCipherText.addTextChangedListener(object : SimpleTextWatcher() {
            override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) {
                btnDecrypt.isEnabled = s?.toString()?.trim()?.isNotEmpty() ?: false
            }
        })
        btnEncrypt.setOnClickListener {
            tvContentShow.text = etContent.text
            etContent.setText("", true)
            val encrypted = if (mode == 0) {
                SecureCrypto.encrypt(tvContentShow.text.toString().toByteArray(), this::onCryptoFailed)
            } else {
                SecureCrypto.wrap(btnGenerateKey.tag as? SecretKey, this::onCryptoFailed)
            }
            tvCipherText.text = encode(encrypted)
        }
        btnDecrypt.setOnClickListener {
            val content = if (mode == 0) {
                SecureCrypto.decrypt(decode(tvCipherText.text.toString()), this::onCryptoFailed).run {
                    if (this == null) "" else String(this)
                }
            } else {
                SecureCrypto.unwrap(decode(tvCipherText.text.toString()), "AES", SecretKey::class.java, this::onCryptoFailed).run {
                    if (this == null) "" else encode(this.encoded)
                }
            }
            etContent.setText(content, true)
            etContent.setSelection(etContent.length())
        }
        btnGenerateKey.setOnClickListener {
            val keyGenerator = KeyGenerator.getInstance("AES")
            keyGenerator.init(256, SecureRandom.getInstance("SHA1PRNG"))
            val secretKey = keyGenerator.generateKey()
            btnGenerateKey.tag = secretKey
            etContent.setText(encode(secretKey.encoded), true)
        }
    }

    private fun encode(bytes: ByteArray?): String? {
        return if (bytes == null) {
            null
        } else {
            Base64.encodeToString(bytes, Base64.NO_WRAP)
        }
    }

    private fun decode(string: String?): ByteArray? {
        return if (string == null) {
            null
        } else {
            Base64.decode(string, Base64.NO_WRAP)
        }
    }

    private fun onCryptoFailed(tr: Throwable) {
        tr.printStackTrace()
        Toast.makeText(this, tr.toString(), Toast.LENGTH_LONG).show()
    }

    override fun onCreateOptionsMenu(menu: Menu?): Boolean {
        menuInflater.inflate(R.menu.menu_main, menu)
        menu?.findItem(R.id.menu_switch)?.isChecked = mode != 0
        return super.onCreateOptionsMenu(menu)
    }

    override fun onOptionsItemSelected(item: MenuItem?): Boolean {
        when (item?.itemId) {
            R.id.menu_safe -> {
                startActivity(Intent(this, ThreadSafeActivity::class.java))
            }
            R.id.menu_switch -> {
                item.isChecked = !item.isChecked
                mode = if (item.isChecked) 1 else 0
                checkModeChanged()
            }
        }
        return super.onOptionsItemSelected(item)
    }

    override fun onStart() {
        super.onStart()
        checkModeChanged()
    }

    /**
     * 确认加解密模式
     */
    private fun checkModeChanged() {
        if (mode == 0) {
            if (btnGenerateKey.visibility == View.VISIBLE) {
                // changed
                btnGenerateKey.visibility = View.GONE
                btnGenerateKey.tag = null
                btnEncrypt.text = "加密"
                btnDecrypt.text = "解密"
                etContent.setText("", true)
                etContent.isEditable = true
                showSoftInput(etContent)
                tvContentShow.text = ""
                tvCipherText.text = ""
            }
        } else {
            if (btnGenerateKey.visibility != View.VISIBLE) {
                // changed
                btnGenerateKey.visibility = View.VISIBLE
                btnGenerateKey.tag = null
                btnEncrypt.text = "加密密钥"
                btnDecrypt.text = "解密密钥"
                etContent.setText("", true)
                etContent.isEditable = false
                hideSoftInput()
                tvContentShow.text = ""
                tvCipherText.text = ""
            }
        }
    }


}

open class SimpleTextWatcher : TextWatcher {

    override fun afterTextChanged(s: Editable?) {

    }

    override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) {

    }

    override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) {

    }
}
