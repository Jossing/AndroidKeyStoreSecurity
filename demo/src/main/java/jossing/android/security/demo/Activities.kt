package jossing.android.security.demo

import android.app.Activity
import android.content.Context
import android.view.View
import android.view.inputmethod.InputMethodManager

/**
 *
 * @author jossing
 * @date 2019-05-11
 */

fun Activity.showSoftInput(focusableView: View): Boolean {
    return if (focusableView.requestFocus()) {
        val imm = getSystemService(Context.INPUT_METHOD_SERVICE) as? InputMethodManager
        imm?.showSoftInput(focusableView, InputMethodManager.SHOW_IMPLICIT) ?: false
    } else {
        false
    }
}


fun Activity.hideSoftInput(): Boolean {
    val imm = getSystemService(Context.INPUT_METHOD_SERVICE) as? InputMethodManager
    return imm?.hideSoftInputFromWindow(window.decorView.windowToken, InputMethodManager.HIDE_NOT_ALWAYS) ?: false
}