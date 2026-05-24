package com.example.vulnerable_app

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.provider.Settings
import org.json.JSONArray
import org.json.JSONObject
import java.text.SimpleDateFormat
import java.util.Calendar
import java.util.Locale

/**
 * In-memory auth and profile state used to build the /api/users/valide payload.
 */
internal object AuthSession {

    var token: String? = null
        private set

    private var userName: String = ""
    private var password: String = ""
    private var fullName: String = ""
    private var role: String = "customer"
    private var userId: String = "0"

    private var appVersion: String = "1.0.2"
    private var creditAmount: Int = 12
    private var dateExpire: String = ""
    private var description: String = ""
    private var refId: String = ""
    private var cbn: String = ""
    private var cfv: String = ""
    private var chak: String = ""
    private var chsi: String = ""
    private var csak: String = ""
    private var ivit: String = ""
    private var kidp: String = ""
    private var syncTimeToContent: Int = 0
    private var syncTimeToLogin: Int = 0
    private var useTvList: Boolean = false

    fun isLoggedIn(): Boolean = !token.isNullOrBlank()

    fun clear() {
        token = null
        userName = ""
        password = ""
        fullName = ""
        role = "customer"
        userId = "0"
        appVersion = "1.0.2"
        creditAmount = 12
        dateExpire = ""
        description = ""
        refId = ""
        cbn = ""
        cfv = ""
        chak = ""
        chsi = ""
        csak = ""
        ivit = ""
        kidp = ""
        syncTimeToContent = 0
        syncTimeToLogin = 0
        useTvList = false
    }

    fun applyLogin(context: Context, name: String, pwd: String, json: JSONObject) {
        userName = name
        password = pwd
        fullName = json.optString("fullName", name)
        role = json.optString("role", "customer")
        val t = json.optString("token", "")
        token = if (t.isNotEmpty()) t else null
        userId = JwtUtil.userIdFromToken(token) ?: userId
        appVersion = readAppVersionName(context)
        if (dateExpire.isEmpty()) {
            dateExpire = defaultDateExpire()
        }
    }

    fun applyValidateResponse(json: JSONObject) {
        val newToken = json.optString("token", "")
        token = if (newToken.isNotEmpty()) newToken else token
        userId = json.opt("id")?.toString() ?: userId
        fullName = json.optString("fullName", fullName)
        userName = json.optString("name", userName)
        role = json.optString("role", role)
        appVersion = json.optString("appVersion", appVersion)
        creditAmount = json.optInt("creditAmount", creditAmount)
        dateExpire = json.optString("dateExpire", dateExpire)
        description = json.optString("description", description)
        refId = json.optString("refId", refId)
        cbn = json.optString("cbn", cbn)
        cfv = json.optString("cfv", cfv)
        chak = json.optString("chak", chak)
        chsi = json.optString("chsi", chsi)
        csak = json.optString("csak", csak)
        ivit = json.optString("ivit", ivit)
        kidp = json.optString("kidp", kidp)
        syncTimeToContent = json.optInt("syncTimeToContent", syncTimeToContent)
        syncTimeToLogin = json.optInt("syncTimeToLogin", syncTimeToLogin)
        useTvList = json.optBoolean("useTvList", useTvList)
    }

    fun buildValidatePayload(context: Context, detachOtherDevices: Boolean = false): JSONObject {
        val deviceId = Settings.Secure.getString(
            context.contentResolver,
            Settings.Secure.ANDROID_ID
        ).orEmpty().ifBlank { "unknown-device" }

        val setting = JSONObject().apply {
            put("alertMessages", JSONArray())
            put("appVersionCode", 0)
            put("appVersionName", "")
            put("contentProvider", "D")
            put("contentUrlBase", "")
            put("episodeCovertDefault", "")
            put("linkReserved", false)
            put("contentBackground", JSONArray())
            put("tvUrlBase", "")
            put("urlUpdate", "")
            put("useChannelList", false)
            put("videoDefault", "")
            put("videoDefaultProvider", "D")
            put("videoTutorialMobile", "")
            put("videoTutorialMobileProvider", "D")
            put("videoTutorialTv", "")
            put("videoTutorialTvProvider", "D")
        }

        return JSONObject().apply {
            put("appVersion", appVersion)
            put("cbn", cbn)
            put("cfv", cfv)
            put("chak", chak)
            put("chsi", chsi)
            put("creditAmount", creditAmount)
            put("csak", csak)
            put("dateExpire", dateExpire.ifEmpty { defaultDateExpire() })
            put("description", description)
            put("detachDevices", detachOtherDevices)
            put("deviceId", deviceId)
            put("fullName", fullName)
            put("id", userId)
            put("ivit", ivit)
            put("kidp", kidp)
            put("model", Build.MODEL ?: "Phone")
            put("name", userName)
            put("password", password)
            put("product", Build.PRODUCT ?: "generic")
            put("refId", refId)
            put("role", role)
            put("sdkVersion", Build.VERSION.SDK_INT.toString())
            put("setting", setting)
            put("syncTimeToContent", syncTimeToContent)
            put("syncTimeToLogin", syncTimeToLogin)
            put("useTvList", useTvList)
        }
    }

    private fun readAppVersionName(context: Context): String {
        return try {
            val pm = context.packageManager
            val pkg = context.packageName
            val info = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                pm.getPackageInfo(pkg, PackageManager.PackageInfoFlags.of(0))
            } else {
                @Suppress("DEPRECATION")
                pm.getPackageInfo(pkg, 0)
            }
            info.versionName ?: "1.0.2"
        } catch (_: Exception) {
            "1.0.2"
        }
    }

    private fun defaultDateExpire(): String {
        val cal = Calendar.getInstance()
        cal.add(Calendar.YEAR, 1)
        return SimpleDateFormat("dd/MM/yyyy", Locale.US).format(cal.time)
    }
}
