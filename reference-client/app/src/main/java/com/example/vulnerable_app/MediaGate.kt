package com.example.vulnerable_app

import android.app.AlertDialog
import android.content.Intent
import android.widget.Toast
import androidx.fragment.app.FragmentActivity
import java.util.concurrent.Executors

/**
 * Runs [ApiClient.validate] on a worker thread before media actions (open details, play, etc.).
 */
internal object MediaGate {

    private val executor = Executors.newSingleThreadExecutor()

    fun runAfterValidate(activity: FragmentActivity, onSuccess: Runnable) {
        if (!AuthSession.isLoggedIn()) {
            activity.startActivity(
                Intent(activity, LoginActivity::class.java)
                    .addFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP)
            )
            return
        }
        executor.execute {
            dispatchValidateResult(activity, ApiClient.validate(activity.applicationContext), onSuccess)
        }
    }

    private fun dispatchValidateResult(
        activity: FragmentActivity,
        result: ValidateResult,
        onSuccess: Runnable
    ) {
        activity.runOnUiThread {
            if (activity.isFinishing) return@runOnUiThread
            when (result) {
                is ValidateResult.Success -> onSuccess.run()
                is ValidateResult.OtherDeviceConflict -> showDetachOtherDeviceDialog(
                    activity,
                    result.message
                )
                is ValidateResult.ExpiredTokenOfferDetach -> showDetachOtherDeviceDialog(
                    activity,
                    activity.getString(R.string.token_expired_detach_prompt)
                )
                is ValidateResult.Error ->
                    Toast.makeText(activity, result.message, Toast.LENGTH_LONG).show()
            }
        }
    }

    private fun showDetachOtherDeviceDialog(
        activity: FragmentActivity,
        message: String
    ) {
        AlertDialog.Builder(activity)
            .setMessage(message.ifBlank { activity.getString(R.string.device_conflict_default_message) })
            .setPositiveButton(R.string.device_conflict_ok) { _, _ ->
                executor.execute {
                    val ctx = activity.applicationContext
                    val detachResult = ApiClient.validate(
                        context = ctx,
                        detachOtherDevice = true,
                        applySessionOnSuccess = false
                    )
                    activity.runOnUiThread {
                        if (activity.isFinishing) return@runOnUiThread
                        AuthSession.clear()
                        activity.startActivity(
                            Intent(activity, LoginActivity::class.java).apply {
                                addFlags(
                                    Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK
                                )
                            }
                        )
                        if (detachResult is ValidateResult.Error) {
                            Toast.makeText(ctx, detachResult.message, Toast.LENGTH_LONG).show()
                        }
                    }
                }
            }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }
}
