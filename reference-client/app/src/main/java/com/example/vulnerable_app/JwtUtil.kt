package com.example.vulnerable_app

import android.util.Base64
import org.json.JSONObject

internal object JwtUtil {
    fun payloadJson(token: String?): JSONObject? {
        if (token.isNullOrBlank()) return null
        val parts = token.split('.')
        if (parts.size < 2) return null
        return try {
            val decoded = Base64.decode(
                parts[1],
                Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING
            )
            JSONObject(String(decoded, Charsets.UTF_8))
        } catch (_: Exception) {
            null
        }
    }

    fun userIdFromToken(token: String?): String? {
        val payload = payloadJson(token) ?: return null
        if (!payload.has("id")) return null
        return payload.get("id").toString()
    }
}
