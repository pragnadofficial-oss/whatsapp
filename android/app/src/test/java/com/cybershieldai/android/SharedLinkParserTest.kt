package com.cybershieldai.android

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class SharedLinkParserTest {
    @Test
    fun extractsAndNormalizesSupportedLinksFromSharedText() {
        assertEquals(
            listOf("https://example.com/path", "http://example.org/"),
            SharedLinkParser.extract("Check https://example.com/path). Also http://example.org/")
        )
        assertEquals(listOf("https://example.com"), SharedLinkParser.extract("example.com"))
        assertEquals(
            listOf("https://example.com:8443/path?x=1#section"),
            SharedLinkParser.extract("example.com:8443/path?x=1#section")
        )
    }

    @Test
    fun returnsMultipleUniqueLinksForTheUserToChoose() {
        assertEquals(
            listOf("https://one.example/", "https://two.example/"),
            SharedLinkParser.extract("https://one.example/ https://two.example/ https://one.example/")
        )
        assertEquals(
            listOf("https://good.example/"),
            SharedLinkParser.extract("ftp://unsupported.example/ https://good.example/")
        )
    }

    @Test
    fun rejectsMalformedAndUnsupportedCandidates() {
        assertNull(SharedLinkParser.validateAndNormalize("javascript:alert(1)"))
        assertNull(SharedLinkParser.validateAndNormalize("ftp://example.com/file"))
        assertNull(SharedLinkParser.validateAndNormalize("https:///missing-host"))
        assertNull(SharedLinkParser.validateAndNormalize("https://bad..example/"))
        assertNull(SharedLinkParser.validateAndNormalize("https://user:secret@example.com/"))
        assertNull(SharedLinkParser.validateAndNormalize("https://example.com:70000/"))
    }

    @Test
    fun openingRequiresCompletedAssessmentAndNeverAllowsMaliciousOrInvalidVerdicts() {
        assertFalse(OpenDecision.canOpen(true, Verdict.MALICIOUS, "https://example.com/"))
        assertFalse(OpenDecision.canOpen(true, Verdict.SAFE, "https://example.com/", blocked = true))
        assertFalse(OpenDecision.canOpen(false, Verdict.SAFE, "https://example.com/"))
        assertFalse(OpenDecision.canOpen(true, Verdict.INVALID, "https://example.com/"))
        assertTrue(OpenDecision.canOpen(true, Verdict.SUSPICIOUS, "https://example.com/"))
        assertTrue(OpenDecision.canOpen(true, Verdict.UNKNOWN, "https://example.com/"))
        assertTrue(OpenDecision.canOpen(true, Verdict.SAFE, "https://example.com/"))
    }

    @Test
    fun assessmentCopyKeepsAllVerdictsDistinctAndDoesNotPromiseSafety() {
        assertTrue(AssessmentCopy.headline(Verdict.MALICIOUS, true).contains("BLOCKED"))
        assertTrue(AssessmentCopy.explanation(Verdict.MALICIOUS).contains("Do not open"))
        assertTrue(AssessmentCopy.headline(Verdict.SUSPICIOUS, false).contains("SUSPICIOUS"))
        assertTrue(AssessmentCopy.explanation(Verdict.UNKNOWN).contains("Unknown does not mean safe"))
        assertTrue(AssessmentCopy.explanation(Verdict.SAFE).contains("not a guarantee"))
    }

    @Test
    fun failedOrMalformedScanCannotEnableOpening() {
        assertFalse(OpenDecision.canOpen(false, Verdict.UNKNOWN, "https://example.com/"))
        assertFalse(OpenDecision.canOpen(false, Verdict.SAFE, "not a url"))
    }

    @Test
    fun productionBackendRequiresHttpsAndLocalDevelopmentHasNarrowHttpExceptions() {
        assertEquals("https://scanner.example", ServerConfiguration.normalizeBaseUrl("https://scanner.example/"))
        assertNull(ServerConfiguration.normalizeBaseUrl("http://scanner.example"))
        assertEquals("http://10.0.2.2:3000", ServerConfiguration.normalizeBaseUrl("http://10.0.2.2:3000/"))
        assertNull(ServerConfiguration.normalizeBaseUrl("http://192.168.1.20:3000"))
        assertNull(ServerConfiguration.normalizeBaseUrl("https://user:pass@scanner.example"))
    }
}
