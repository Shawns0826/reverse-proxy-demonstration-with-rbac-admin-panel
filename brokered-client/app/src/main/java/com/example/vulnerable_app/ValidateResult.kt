package com.example.vulnerable_app

/** Outcome of [ApiClient.validate]. */
internal sealed class ValidateResult {
    object Success : ValidateResult()
    data class Error(val message: String) : ValidateResult()
    /** HTTP 403: session is bound to another device; retry with detachDevices=true after user confirms. */
    data class OtherDeviceConflict(val message: String) : ValidateResult()
    /** HTTP 401: invalid/expired JWT; offer detach-other-device retry (same valide + detachDevices=true). */
    data class ExpiredTokenOfferDetach(val serverMessage: String) : ValidateResult()
}
