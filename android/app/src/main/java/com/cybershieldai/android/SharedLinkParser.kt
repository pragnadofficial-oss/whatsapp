package com.cybershieldai.android

import java.net.URI
import java.util.Locale

object SharedLinkParser {
    private val linkPattern = Regex(
        """(?i)(?:https?://|www\.)[^\s<>"'`()\[\]{}]+|(?<![@\w])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}(?::\d{1,5})?(?:[/?#][^\s<>"'`()\[\]{}]*)?"""
    )
    private val domainPattern = Regex(
        """(?i)^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$"""
    )

    fun extract(text: String): List<String> {
        val links = LinkedHashSet<String>()
        for (match in linkPattern.findAll(text)) {
            val prefix = text.substring(0, match.range.first)
            val previousToken = prefix.substring(prefix.indexOfLast { it.isWhitespace() } + 1)
            if (Regex("""(?i)^[a-z][a-z\d+.-]*://""").containsMatchIn(previousToken)) continue
            val cleaned = trimTrailingPunctuation(match.value)
            val normalized = validateAndNormalize(cleaned) ?: continue
            links.add(normalized)
        }
        return links.toList()
    }

    fun validateAndNormalize(candidate: String): String? {
        if (candidate.isBlank() || candidate.length > 2048 || candidate.any { it.isWhitespace() || it.isISOControl() }) {
            return null
        }
        val hasScheme = Regex("""^[a-z][a-z\d+.-]*:""", RegexOption.IGNORE_CASE).containsMatchIn(candidate)
        val hostnameWithPort = Regex("""^[^/:]+:\d+(?:/|$|[?#])""").containsMatchIn(candidate)
        val normalized = when {
            candidate.startsWith("https://", ignoreCase = true) ||
                candidate.startsWith("http://", ignoreCase = true) -> candidate
            hasScheme && !hostnameWithPort -> return null
            candidate.startsWith("www.", ignoreCase = true) -> "https://$candidate"
            else -> "https://$candidate"
        }
        val uri = runCatching { URI(normalized) }.getOrNull() ?: return null
        val scheme = uri.scheme?.lowercase(Locale.ROOT)
        if (scheme != "http" && scheme != "https") return null
        val host = uri.host?.lowercase(Locale.ROOT)?.removePrefix("[")?.removeSuffix("]") ?: return null
        if (uri.rawUserInfo != null || host.isBlank() || host.endsWith('.')) return null
        if (host.any { it.isWhitespace() || it.isISOControl() } || host.startsWith('.') || host.contains("..")) return null
        if (uri.port !in -1..65535 || uri.port == 0 || !validPortSyntax(uri.rawAuthority.orEmpty())) return null
        if (host.contains(':')) {
            if (!host.matches(Regex("""[0-9a-f:.]+""", RegexOption.IGNORE_CASE))) return null
        } else if (!domainPattern.matches(host) && !isIpv4(host)) {
            return null
        }
        return normalized
    }

    private fun isIpv4(host: String): Boolean {
        val parts = host.split('.')
        return parts.size == 4 && parts.all { part ->
            part.toIntOrNull()?.let { it in 0..255 && (part == "0" || !part.startsWith('0')) } == true
        }
    }

    private fun trimTrailingPunctuation(value: String): String {
        var result = value.trimEnd('.', ',', '!', '?', ';', ':')
        while (result.endsWith(')') && result.count { it == ')' } > result.count { it == '(' }) {
            result = result.dropLast(1)
        }
        while (result.endsWith(']') && result.count { it == ']' } > result.count { it == '[' }) {
            result = result.dropLast(1)
        }
        return result
    }
}

enum class Verdict {
    SAFE,
    SUSPICIOUS,
    UNKNOWN,
    MALICIOUS,
    INVALID
}

object OpenDecision {
    fun canOpen(
        scanCompleted: Boolean,
        verdict: Verdict,
        normalizedUrl: String?,
        blocked: Boolean = false
    ): Boolean {
        return scanCompleted
            && !blocked
            && verdict != Verdict.MALICIOUS
            && verdict != Verdict.INVALID
            && SharedLinkParser.validateAndNormalize(normalizedUrl.orEmpty()) != null
    }
}

object ServerConfiguration {
    private val localHttpHosts = setOf("localhost", "127.0.0.1", "10.0.2.2", "::1")

    fun normalizeBaseUrl(candidate: String): String? {
        if (candidate.isBlank() || candidate.length > 2048 || candidate.any { it.isWhitespace() || it.isISOControl() }) {
            return null
        }
        val uri = runCatching { URI(candidate) }.getOrNull() ?: return null
        val scheme = uri.scheme?.lowercase(Locale.ROOT)
        val host = uri.host?.lowercase(Locale.ROOT)?.removePrefix("[")?.removeSuffix("]") ?: return null
        if (scheme != "https" && !(scheme == "http" && host in localHttpHosts)) return null
        if (uri.rawUserInfo != null || uri.query != null || uri.fragment != null || uri.port !in -1..65535) return null
        if (uri.port == 0 || host.contains("..") || !validPortSyntax(uri.rawAuthority.orEmpty())) return null
        return candidate.trimEnd('/')
    }

    private fun validPortSyntax(authority: String): Boolean {
        val hostPort = authority.substringAfterLast('@', authority)
        if (hostPort.startsWith('[')) {
            val closingBracket = hostPort.indexOf(']')
            if (closingBracket < 0) return false
            val suffix = hostPort.substring(closingBracket + 1)
            return suffix.isEmpty() || suffix.matches(Regex(""":\d+"""))
        }
        val colon = hostPort.lastIndexOf(':')
        return colon < 0 || hostPort.substring(colon + 1).matches(Regex("""\d+"""))
    }
}

object AssessmentCopy {
    fun headline(verdict: Verdict, blocked: Boolean): String = when {
        verdict == Verdict.MALICIOUS || blocked -> "BLOCKED IN CYBERSHIELD AI"
        verdict == Verdict.SUSPICIOUS -> "SUSPICIOUS — USE CAUTION"
        verdict == Verdict.UNKNOWN -> "UNKNOWN — NOT ENOUGH EVIDENCE"
        verdict == Verdict.SAFE -> "NO CONFIGURED CHECKS FOUND A THREAT"
        else -> "INVALID LINK"
    }

    fun explanation(verdict: Verdict): String = when (verdict) {
        Verdict.MALICIOUS -> "A confirmed malicious result was returned. Do not open this link. This block applies only inside CyberShield AI."
        Verdict.SUSPICIOUS -> "Warning signs were found, but this is not a confirmed malicious verdict. Opening is a separate choice."
        Verdict.UNKNOWN -> "The scan was inconclusive or reputation evidence was insufficient. Unknown does not mean safe."
        Verdict.SAFE -> "No configured checks found a threat. This is not a guarantee that the link is safe."
        Verdict.INVALID -> "The server could not validate this link."
    }
}
