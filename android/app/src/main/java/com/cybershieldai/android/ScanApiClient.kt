package com.cybershieldai.android

import org.json.JSONArray
import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.URL

data class ScanAssessment(
    val normalizedUrl: String,
    val hostname: String,
    val verdict: Verdict,
    val riskScore: Int?,
    val confidence: String,
    val reasons: List<String>,
    val checks: List<String>,
    val recommendation: String,
    val blocked: Boolean
)

class ScanApiClient {
    fun scan(
        baseUrl: String,
        apiToken: String?,
        sharedUrl: String,
        consentToExternalScan: Boolean
    ): ScanAssessment {
        val normalizedBase = ServerConfiguration.normalizeBaseUrl(baseUrl)
            ?: throw IllegalArgumentException("Set a valid HTTPS server URL. HTTP is allowed only for localhost and the Android emulator host.")
        val normalizedSharedUrl = SharedLinkParser.validateAndNormalize(sharedUrl)
            ?: throw IllegalArgumentException("The shared link is not a valid HTTP or HTTPS URL.")
        val endpoint = URL("${normalizedBase.trimEnd('/')}/api/scan/url")
        val connection = endpoint.openConnection() as HttpURLConnection
        connection.instanceFollowRedirects = false
        connection.connectTimeout = 10_000
        connection.readTimeout = 25_000
        connection.requestMethod = "POST"
        connection.doOutput = true
        connection.setRequestProperty("Accept", "application/json")
        connection.setRequestProperty("Content-Type", "application/json; charset=utf-8")
        apiToken?.takeIf { it.isNotBlank() }?.let {
            connection.setRequestProperty("X-API-Key", it)
        }
        try {
            val request = JSONObject()
                .put("url", normalizedSharedUrl)
                .put("consentToExternalScan", consentToExternalScan)
                .toString()
            connection.outputStream.use { output ->
                output.write(request.toByteArray(Charsets.UTF_8))
            }
            val status = connection.responseCode
            val stream = if (status in 200..299) connection.inputStream else connection.errorStream
            val body = stream?.use { readBounded(it) }.orEmpty()
            val response = runCatching { JSONObject(body) }.getOrElse {
                throw IllegalStateException("Could not complete scan: the server returned an invalid response.")
            }
            if (status == HttpURLConnection.HTTP_UNAUTHORIZED) {
                throw IllegalStateException("The server requires or rejected an API token. Check the token in Server settings.")
            }
            if (status !in 200..299 || !response.optBoolean("ok")) {
                val detail = response.optString("error").takeIf { it.isNotBlank() }
                    ?: "The server could not complete the scan (HTTP $status)."
                throw IllegalStateException(detail)
            }
            val result = response.optJSONObject("result")
                ?: throw IllegalStateException("Could not complete scan: the server response had no result.")
            val rawVerdict = result.optString("verdict").uppercase()
            val verdict = runCatching { Verdict.valueOf(rawVerdict) }.getOrElse {
                throw IllegalStateException("Could not complete scan: the server returned an unknown verdict.")
            }
            if (verdict == Verdict.INVALID) {
                throw IllegalStateException(result.optString("error").ifBlank { "The server rejected this URL as invalid." })
            }
            val normalizedUrl = result.optString("normalizedUrl").ifBlank {
                result.optString("url")
            }
            val validatedUrl = SharedLinkParser.validateAndNormalize(normalizedUrl)
                ?: throw IllegalStateException("Could not complete scan: the server returned an invalid normalized URL.")
            val blocked = verdict == Verdict.MALICIOUS || result.optBoolean("blocked")
            val finalVerdict = if (blocked) Verdict.MALICIOUS else verdict
            val score = result.opt("riskScore").let { value ->
                (value as? Number)?.toInt()?.takeIf { it in 0..100 }
            }
            return ScanAssessment(
                normalizedUrl = validatedUrl,
                hostname = result.optString("hostname").ifBlank {
                    URL(validatedUrl).host
                },
                verdict = finalVerdict,
                riskScore = score,
                confidence = result.optString("confidence").ifBlank { "unknown" },
                reasons = readStrings(result.optJSONArray("reasons")),
                checks = readChecks(result.optJSONArray("checks")),
                recommendation = result.optString("recommendation"),
                blocked = blocked
            )
        } catch (error: java.net.SocketTimeoutException) {
            throw IllegalStateException("Could not complete scan: the server timed out. No link was opened.", error)
        } catch (error: java.io.IOException) {
            throw IllegalStateException("Could not complete scan: the server is unavailable or you are offline. No link was opened.", error)
        } finally {
            connection.disconnect()
        }
    }

    private fun readBounded(input: java.io.InputStream): String {
        val output = java.io.ByteArrayOutputStream()
        val buffer = ByteArray(4096)
        var total = 0
        while (true) {
            val count = input.read(buffer)
            if (count < 0) break
            total += count
            if (total > MAX_RESPONSE_BYTES) {
                throw IllegalStateException("Could not complete scan: the server response was too large.")
            }
            output.write(buffer, 0, count)
        }
        return output.toString(Charsets.UTF_8.name())
    }

    private fun readStrings(array: JSONArray?): List<String> {
        if (array == null) return emptyList()
        return (0 until array.length()).mapNotNull { index ->
            array.optString(index).takeIf { it.isNotBlank() }
        }
    }

    private fun readChecks(array: JSONArray?): List<String> {
        if (array == null) return emptyList()
        return (0 until array.length()).mapNotNull { index ->
            val check = array.optJSONObject(index) ?: return@mapNotNull null
            val provider = check.optString("provider").ifBlank { "Check" }
            val status = check.optString("status").ifBlank { "unavailable" }
            val details = check.optString("details")
            "$provider: $status${if (details.isBlank()) "" else " — $details"}"
        }
    }

    companion object {
        private const val MAX_RESPONSE_BYTES = 128 * 1024
    }
}
