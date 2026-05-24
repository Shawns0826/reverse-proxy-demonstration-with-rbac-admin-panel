package com.example.vulnerable_app

import android.content.Context
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONObject
import java.util.concurrent.TimeUnit

internal object ApiClient {

    private val jsonUtf8 = "application/json; charset=UTF-8".toMediaType()
    private val jsonPlain = "application/json".toMediaType()

    private val client = OkHttpClient.Builder()
        .connectTimeout(20, TimeUnit.SECONDS)
        .readTimeout(30, TimeUnit.SECONDS)
        .build()

    private const val PROVIDER = "com.sticktv.tv"
    private const val LOGIN_UA = "okhttp/3.14.7"
    private const val VALIDATE_UA =
        "G0lmmXG4N54BCW+6LZyXCN+GEbRM2YlyzPQ9vvr+Oqg@okhttp/4.5.0@0620d1f0ca05f336@com.sticktv.tv@fDuh9hW0HHcz9e7Q+J3nbA"

    /** Server message when this deviceId is not the bound session (HTTP 403). */
    private const val OTHER_DEVICE_MESSAGE =
        "El usuario está asignado a otro dispositivo"

    fun login(context: Context, username: String, password: String): String? {
        val base = context.getString(R.string.api_base_url).trimEnd('/')
        val body = JSONObject().apply {
            put("name", username)
            put("password", password)
            put("provider", PROVIDER)
        }.toString()
        val request = Request.Builder()
            .url("$base/api/auths/local")
            .post(body.toRequestBody(jsonPlain))
            .header("Content-Type", "application/json")
            .header("User-Agent", LOGIN_UA)
            .build()
        return executeJson(request) { json -> AuthSession.applyLogin(context, username, password, json) }
    }

    fun validate(
        context: Context,
        detachOtherDevice: Boolean = false,
        applySessionOnSuccess: Boolean = true
    ): ValidateResult {
        val base = context.getString(R.string.api_base_url).trimEnd('/')
        val bearer = AuthSession.token ?: return ValidateResult.Error("Not signed in")
        val body = AuthSession.buildValidatePayload(context, detachOtherDevice).toString()
        val request = Request.Builder()
            .url("$base/api/users/valide")
            .post(body.toRequestBody(jsonUtf8))
            .header("Authorization", "Bearer $bearer")
            .header("Content-Type", "application/json; charset=UTF-8")
            .header("User-Agent", VALIDATE_UA)
            .build()
        return try {
            client.newCall(request).execute().use { response ->
                val bodyStr = response.body?.string().orEmpty()
                when (response.code) {
                    200 -> {
                        try {
                            val json = JSONObject(bodyStr)
                            if (applySessionOnSuccess) {
                                AuthSession.applyValidateResponse(json)
                            }
                            ValidateResult.Success
                        } catch (_: Exception) {
                            ValidateResult.Error("Invalid JSON response")
                        }
                    }
                    401 -> {
                        if (isExpiredOrInvalidTokenBody(bodyStr)) {
                            ValidateResult.ExpiredTokenOfferDetach(parseApiMessage(bodyStr))
                        } else {
                            ValidateResult.Error(parseApiMessage(bodyStr).ifBlank { "HTTP 401" })
                        }
                    }
                    403 -> {
                        if (isOtherDeviceConflict(bodyStr)) {
                            ValidateResult.OtherDeviceConflict(parseApiMessage(bodyStr))
                        } else {
                            ValidateResult.Error(parseApiMessage(bodyStr).ifBlank { "HTTP 403" })
                        }
                    }
                    else -> ValidateResult.Error(parseApiMessage(bodyStr).ifBlank { "HTTP ${response.code}" })
                }
            }
        } catch (e: Exception) {
            ValidateResult.Error(e.message ?: e.javaClass.simpleName)
        }
    }

    private fun isExpiredOrInvalidTokenBody(bodyStr: String): Boolean {
        val m = parseApiMessage(bodyStr).trim()
        if (m.isEmpty()) return false
        if (m.equals("Invalid or expired token", ignoreCase = true)) return true
        if (m.contains("expired", ignoreCase = true) && m.contains("token", ignoreCase = true)) return true
        if (m.contains("invalid", ignoreCase = true) && m.contains("expired", ignoreCase = true)) return true
        return false
    }

    private fun isOtherDeviceConflict(bodyStr: String): Boolean {
        return try {
            val j = JSONObject(bodyStr)
            val msg = j.optString("message", "")
            msg == OTHER_DEVICE_MESSAGE || msg.contains("otro dispositivo", ignoreCase = true)
        } catch (_: Exception) {
            false
        }
    }

    private fun parseApiMessage(bodyStr: String): String {
        return try {
            val err = JSONObject(bodyStr)
            err.optString("error")
                .ifEmpty { err.optString("message") }
                .ifEmpty { bodyStr }
        } catch (_: Exception) {
            bodyStr
        }
    }

    private fun executeJson(request: Request, onSuccess: (JSONObject) -> Unit): String? {
        return try {
            client.newCall(request).execute().use { response ->
                val bodyStr = response.body?.string().orEmpty()
                if (!response.isSuccessful) {
                    return try {
                        val err = JSONObject(bodyStr)
                        err.optString("error")
                            .ifEmpty { err.optString("message") }
                            .ifEmpty { bodyStr.ifBlank { "HTTP ${response.code}" } }
                    } catch (_: Exception) {
                        bodyStr.ifBlank { "HTTP ${response.code}" }
                    }
                }
                try {
                    onSuccess(JSONObject(bodyStr))
                    null
                } catch (_: Exception) {
                    "Invalid JSON response"
                }
            }
        } catch (e: Exception) {
            e.message ?: e.javaClass.simpleName
        }
    }
}
