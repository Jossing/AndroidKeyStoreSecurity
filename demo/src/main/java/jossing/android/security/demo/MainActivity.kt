package jossing.android.security.demo

import androidx.appcompat.app.AppCompatActivity
import android.os.Bundle
import android.text.Editable
import android.text.TextWatcher
import android.util.Base64
import android.widget.Toast
import jossing.android.security.SecureCrypto
import jossing.android.security.SecureCryptoConfig
import kotlinx.android.synthetic.main.activity_main.*

class MainActivity : AppCompatActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        applicationContext.also {
            SecureCryptoConfig.setAppContext { it }
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
            etContent.setText("")
            tvCipherText.text = encode(SecureCrypto.encrypt(tvContentShow.text.toString().toByteArray(), this::onCryptoFailed))
        }
        btnDecrypt.setOnClickListener {
            val content = SecureCrypto.decrypt(decode(tvCipherText.text.toString()), this::onCryptoFailed)
            etContent.setText(if (content == null) "" else String(content))
            etContent.setSelection(etContent.length())
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
}

open class SimpleTextWatcher : TextWatcher {

    override fun afterTextChanged(s: Editable?) {

    }

    override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) {

    }

    override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) {

    }
}
