package jossing.android.security.demo

import android.text.InputFilter
import android.text.SpannableString
import android.text.Spanned
import android.text.TextUtils
import android.widget.EditText

/**
 *
 * @author jossing
 * @date 2019-05-11
 */

private class EditableInputFilter : InputFilter {

    internal var isEditable: Boolean = true

    override fun filter(
        source: CharSequence,
        start: Int,
        end: Int,
        dest: Spanned,
        dstart: Int,
        dend: Int
    ): CharSequence? = if (isEditable) null else {
        val spanned = SpannableString(dest)
        TextUtils.copySpansFrom(dest, 0, dest.length, null, spanned, 0)
        spanned
    }
}

private val editableInputFilterInternal by lazy { EditableInputFilter() }

private val EditText.editableInputFilter get() = editableInputFilterInternal

var EditText.isEditable
    get() = run {
        editableInputFilter.isEditable = isFocusable && isFocusableInTouchMode
        editableInputFilter.isEditable
    }
    set(value) {
        if (!filters.contains(editableInputFilter)) {
            filters = filters.toMutableList().apply { add(editableInputFilter) }.toTypedArray()
        }
        editableInputFilter.isEditable = value
        isFocusable = value
        isFocusableInTouchMode = value
    }

fun EditText.setText(content: CharSequence?, ignoreEditable: Boolean) {
    if (!ignoreEditable) {
        setText(content)
    } else {
        val isEditable = this.isEditable
        if (!isEditable) {
            this.isEditable = true
        }
        setText(content)
        if (!isEditable) {
            this.isEditable = false
        }
    }
}
