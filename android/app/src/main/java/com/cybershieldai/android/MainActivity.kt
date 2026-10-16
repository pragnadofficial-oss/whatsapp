package com.cybershieldai.android

import android.app.Activity
import android.app.AlertDialog
import android.content.Intent
import android.graphics.Color
import android.graphics.Typeface
import android.graphics.drawable.GradientDrawable
import android.net.Uri
import android.os.Bundle
import android.text.InputType
import android.text.Editable
import android.text.TextWatcher
import android.view.Gravity
import android.view.View
import android.view.ViewGroup
import android.widget.Button
import android.widget.CheckBox
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView

class MainActivity : Activity() {
    private lateinit var urlInput: EditText
    private lateinit var serverLabel: TextView
    private lateinit var consentCheckbox: CheckBox
    private lateinit var statusText: TextView
    private lateinit var resultContainer: LinearLayout
    private lateinit var scanButton: Button
    private lateinit var openButton: Button
    private lateinit var returnButton: Button
    private var receivedFromShare = false
    private var lastScannedInput: String? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.statusBarColor = COLOR_BACKGROUND
        window.navigationBarColor = COLOR_BACKGROUND
        window.decorView.systemUiVisibility = 0
        receivedFromShare = intent?.action == Intent.ACTION_SEND
        setContentView(createScreen())
        savedInstanceState?.getString(STATE_URL)?.let { urlInput.setText(it) }
        returnButton.visibility = if (receivedFromShare) View.VISIBLE else View.GONE
        if (savedInstanceState == null) handleIncomingIntent(intent)
        updateServerLabel()
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        handleIncomingIntent(intent)
    }

    override fun onSaveInstanceState(outState: Bundle) {
        outState.putString(STATE_URL, urlInput.text.toString())
        super.onSaveInstanceState(outState)
    }

    private fun createScreen(): View {
        val scroll = ScrollView(this)
        scroll.setBackgroundColor(COLOR_BACKGROUND)
        scroll.setOnApplyWindowInsetsListener { view, insets ->
            view.setPadding(0, insets.systemWindowInsetTop, 0, insets.systemWindowInsetBottom)
            insets
        }
        val content = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(22), dp(24), dp(22), dp(32))
        }
        scroll.addView(content)

        content.addView(text("CyberShield AI", 26, COLOR_TEXT, bold = true))
        content.addView(text(
            "Share a link here to scan it before choosing whether to open it. The scan never visits the submitted site.",
            15,
            COLOR_MUTED
        ), spacing(top = 8, bottom = 20))
        content.addView(text("Link to assess", 14, COLOR_TEXT, bold = true))
        urlInput = EditText(this).apply {
            hint = "Share a link from another app, or enter one"
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_URI
            setSingleLine(false)
            minLines = 2
            setTextColor(COLOR_TEXT)
            setHintTextColor(COLOR_MUTED)
            setPadding(dp(12), dp(10), dp(12), dp(10))
            background = rounded(COLOR_SURFACE, COLOR_BORDER)
            contentDescription = "HTTP or HTTPS link to scan"
        }
        content.addView(urlInput, spacing(top = 7, bottom = 13))

        serverLabel = text("", 13, COLOR_MUTED)
        content.addView(serverLabel, spacing(bottom = 8))
        val settingsButton = button("Server settings")
        settingsButton.setOnClickListener { showServerSettings() }
        content.addView(settingsButton, spacing(bottom = 16))

        consentCheckbox = CheckBox(this).apply {
            text = "Share this URL with configured reputation providers for this scan only"
            setTextColor(COLOR_TEXT)
            textSize = 14f
            isChecked = false
            contentDescription = "Optional consent to share this link with configured external threat-intelligence providers"
        }
        content.addView(consentCheckbox, spacing(bottom = 12))
        content.addView(text(
            "External sharing is off unless you check this box. Provider terms and retention policies apply.",
            12,
            COLOR_MUTED
        ), spacing(bottom = 16))

        scanButton = button("Scan link")
        scanButton.setOnClickListener { scanSelectedLink() }
        content.addView(scanButton, spacing(bottom = 12))

        statusText = text(
            "Choose a link using Share → CyberShield AI, or enter a URL above.",
            14,
            COLOR_MUTED
        )
        statusText.contentDescription = "Scan status"
        content.addView(statusText, spacing(top = 4, bottom = 10))

        resultContainer = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(14), dp(14), dp(14), dp(14))
            background = rounded(COLOR_SURFACE, COLOR_BORDER)
            visibility = View.GONE
            importantForAccessibility = View.IMPORTANT_FOR_ACCESSIBILITY_YES
        }
        content.addView(resultContainer, spacing(bottom = 14))

        openButton = button("Open link")
        openButton.visibility = View.GONE
        openButton.setOnClickListener { openAssessedLink() }
        content.addView(openButton, spacing(bottom = 10))

        returnButton = button("Return to the sharing app")
        returnButton.visibility = View.GONE
        returnButton.setOnClickListener { finish() }
        content.addView(returnButton)
        urlInput.addTextChangedListener(object : TextWatcher {
            override fun beforeTextChanged(sequence: CharSequence?, start: Int, count: Int, after: Int) = Unit
            override fun onTextChanged(sequence: CharSequence?, start: Int, before: Int, count: Int) = Unit

            override fun afterTextChanged(editable: Editable?) {
                if (openButton.tag != null && editable?.toString() != lastScannedInput) {
                    openButton.visibility = View.GONE
                    openButton.isEnabled = false
                    openButton.tag = null
                    resultContainer.visibility = View.GONE
                    setStatus("The link changed after the assessment. Scan it again before opening.")
                }
            }
        })
        return scroll
    }

    private fun handleIncomingIntent(incoming: Intent?) {
        if (incoming?.action != Intent.ACTION_SEND || incoming.type != "text/plain") return
        receivedFromShare = true
        returnButton.visibility = View.VISIBLE
        val sharedText = incoming.getCharSequenceExtra(Intent.EXTRA_TEXT)?.toString().orEmpty()
        val links = SharedLinkParser.extract(sharedText)
        when (links.size) {
            0 -> {
                urlInput.setText("")
                setStatus("No valid HTTP or HTTPS link was found in the shared text. No message or sender data is collected.")
            }
            1 -> chooseLink(links.single())
            else -> AlertDialog.Builder(this)
                .setTitle("Choose a link to scan")
                .setItems(links.toTypedArray()) { _, index -> chooseLink(links[index]) }
                .setNegativeButton("Cancel", null)
                .show()
        }
    }

    private fun chooseLink(link: String) {
        urlInput.setText(link)
        openButton.visibility = View.GONE
        openButton.isEnabled = false
        openButton.tag = null
        resultContainer.visibility = View.GONE
        setStatus("Review the selected link, then tap Scan link. It will not be opened during scanning.")
    }

    private fun scanSelectedLink() {
        val consentToExternalScan = consentCheckbox.isChecked
        consentCheckbox.isChecked = false
        val candidate = SharedLinkParser.validateAndNormalize(urlInput.text.toString().trim())
        if (candidate == null) {
            showFailure("Enter or share a valid HTTP or HTTPS URL. Unsupported schemes and malformed links cannot be scanned.")
            return
        }
        val preferences = getSharedPreferences(PREFERENCES, MODE_PRIVATE)
        val baseUrl = preferences.getString(KEY_SERVER_URL, DEFAULT_SERVER_URL).orEmpty()
        val normalizedBase = ServerConfiguration.normalizeBaseUrl(baseUrl)
        if (normalizedBase == null) {
            showFailure("Configure a valid HTTPS server URL in Server settings before scanning.")
            return
        }

        scanButton.isEnabled = false
        lastScannedInput = urlInput.text.toString()
        openButton.visibility = View.GONE
        openButton.isEnabled = false
        openButton.tag = null
        resultContainer.visibility = View.GONE
        setStatus("Scanning the shared URL. The destination itself is not opened or contacted.")

        Thread {
            try {
                val token = TokenVault(this).read()
                val assessment = ScanApiClient().scan(
                    normalizedBase,
                    token,
                    candidate,
                    consentToExternalScan
                )
                runOnUiThread {
                    if (!isFinishing) {
                        scanButton.isEnabled = true
                        if (urlInput.text.toString() == lastScannedInput) {
                            renderAssessment(assessment)
                        } else {
                            showFailure("The selected link changed while scanning. Scan the current link before opening it.")
                        }
                    }
                }
            } catch (error: Exception) {
                runOnUiThread {
                    if (!isFinishing) {
                        scanButton.isEnabled = true
                        showFailure(error.message ?: "Could not complete scan. No link was opened.")
                    }
                }
            }
        }.start()
    }

    private fun renderAssessment(assessment: ScanAssessment) {
        resultContainer.removeAllViews()
        resultContainer.background = rounded(
            if (assessment.blocked) COLOR_BLOCKED else COLOR_SURFACE,
            if (assessment.blocked) COLOR_RED else COLOR_BORDER
        )
        resultContainer.visibility = View.VISIBLE
        val title = text(
            AssessmentCopy.headline(assessment.verdict, assessment.blocked),
            19,
            if (assessment.blocked) COLOR_RED else COLOR_TEXT,
            bold = true
        )
        title.contentDescription = "Assessment: ${AssessmentCopy.headline(assessment.verdict, assessment.blocked)}"
        resultContainer.addView(title, spacing(bottom = 8))
        resultContainer.addView(text("Host: ${assessment.hostname}", 14, COLOR_TEXT), spacing(bottom = 8))
        resultContainer.addView(text("Scanned URL: ${assessment.normalizedUrl}", 12, COLOR_MUTED), spacing(bottom = 8))
        resultContainer.addView(text(AssessmentCopy.explanation(assessment.verdict), 14, COLOR_TEXT), spacing(bottom = 8))
        resultContainer.addView(text(
            "Confidence: ${assessment.confidence}" +
                (assessment.riskScore?.let { " · Rule-based risk score: $it/100 (not a probability)" } ?: ""),
            13,
            COLOR_MUTED
        ), spacing(bottom = 8))
        if (assessment.recommendation.isNotBlank()) {
            resultContainer.addView(text(assessment.recommendation, 14, COLOR_TEXT), spacing(bottom = 8))
        }
        if (assessment.reasons.isNotEmpty()) {
            resultContainer.addView(text("Reasons", 14, COLOR_TEXT, bold = true), spacing(top = 4, bottom = 4))
            assessment.reasons.forEach { resultContainer.addView(text("• $it", 13, COLOR_MUTED), spacing(bottom = 3)) }
        }
        if (assessment.checks.isNotEmpty()) {
            resultContainer.addView(text("Assessment sources and limits", 14, COLOR_TEXT, bold = true), spacing(top = 8, bottom = 4))
            assessment.checks.forEach { resultContainer.addView(text("• $it", 12, COLOR_MUTED), spacing(bottom = 3)) }
        }
        if (assessment.blocked) {
            setStatus("Blocked inside CyberShield AI. No action here will open or follow this URL.")
            openButton.visibility = View.GONE
            openButton.isEnabled = false
            openButton.tag = null
            returnButton.visibility = View.VISIBLE
            return
        }

        setStatus("Scan completed. Opening is a separate action; review the result before continuing.")
        openButton.text = when (assessment.verdict) {
            Verdict.SAFE -> "Open link in browser"
            Verdict.SUSPICIOUS -> "Open anyway — suspicious"
            Verdict.UNKNOWN -> "Open anyway — unverified"
            else -> "Open link"
        }
        openButton.visibility = View.VISIBLE
        returnButton.visibility = if (receivedFromShare) View.VISIBLE else View.GONE
        openButton.isEnabled = OpenDecision.canOpen(
            scanCompleted = true,
            verdict = assessment.verdict,
            normalizedUrl = assessment.normalizedUrl,
            blocked = assessment.blocked
        )
        openButton.tag = assessment
    }

    private fun openAssessedLink() {
        val assessment = openButton.tag as? ScanAssessment ?: return
        if (!OpenDecision.canOpen(true, assessment.verdict, assessment.normalizedUrl, assessment.blocked)) {
            showFailure("This link cannot be opened from CyberShield AI because it is malicious, invalid, or was not successfully assessed.")
            return
        }
        try {
            startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(assessment.normalizedUrl)))
        } catch (_: android.content.ActivityNotFoundException) {
            showFailure("No browser or compatible app is available to open this link.")
        } catch (_: SecurityException) {
            showFailure("Android refused to open this link. No action was taken.")
        }
    }

    private fun showFailure(message: String) {
        openButton.visibility = View.GONE
        openButton.isEnabled = false
        openButton.tag = null
        resultContainer.visibility = View.GONE
        setStatus("Could not complete scan. No link was opened. $message")
        returnButton.visibility = if (receivedFromShare) View.VISIBLE else View.GONE
    }

    private fun showServerSettings() {
        val preferences = getSharedPreferences(PREFERENCES, MODE_PRIVATE)
        val settings = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(20), dp(8), dp(20), 0)
        }
        val serverInput = EditText(this).apply {
            hint = "https://your-server.example"
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_URI
            setSingleLine(true)
            setText(preferences.getString(KEY_SERVER_URL, DEFAULT_SERVER_URL).orEmpty())
            contentDescription = "CyberShield backend base URL"
        }
        settings.addView(text("Backend base URL", 14, COLOR_TEXT, bold = true))
        settings.addView(serverInput)
        settings.addView(text(
            "Production requires HTTPS. HTTP is accepted only for localhost or the Android emulator host at 10.0.2.2.",
            12,
            COLOR_MUTED
        ), spacing(top = 4, bottom = 12))
        val tokenInput = EditText(this).apply {
            hint = "API token, if the server requires one"
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD
            setSingleLine(true)
            contentDescription = "Optional backend API token"
        }
        settings.addView(text("API token (optional)", 14, COLOR_TEXT, bold = true))
        settings.addView(tokenInput)
        settings.addView(text(
            "The token is encrypted with Android Keystore and sent only to the configured server.",
            12,
            COLOR_MUTED
        ), spacing(top = 4, bottom = 8))
        val clearToken = CheckBox(this).apply {
            text = "Remove saved token"
            setTextColor(COLOR_TEXT)
        }
        settings.addView(clearToken)

        AlertDialog.Builder(this)
            .setTitle("Server settings")
            .setView(settings)
            .setNegativeButton("Cancel", null)
            .setPositiveButton("Save", null)
            .create()
            .also { dialog ->
                dialog.setOnShowListener {
                    dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener {
                        val baseUrl = ServerConfiguration.normalizeBaseUrl(serverInput.text.toString().trim())
                        if (baseUrl == null) {
                            showDialogMessage("Use an HTTPS URL, or HTTP only for localhost or the Android emulator host.")
                            return@setOnClickListener
                        }
                        try {
                            val tokenVault = TokenVault(this)
                            val token = tokenInput.text.toString()
                            if (token.isNotEmpty()) tokenVault.save(token)
                            else if (clearToken.isChecked) tokenVault.clear()
                            val saved = preferences.edit().putString(KEY_SERVER_URL, baseUrl).commit()
                            check(saved) { "Could not save server settings." }
                            updateServerLabel()
                            dialog.dismiss()
                            setStatus("Server settings saved. External provider checks remain off unless you consent for a scan.")
                        } catch (error: Exception) {
                            showDialogMessage(error.message ?: "Could not save server settings.")
                        }
                    }
                }
                dialog.show()
            }
    }

    private fun showDialogMessage(message: String) {
        AlertDialog.Builder(this)
            .setMessage(message)
            .setPositiveButton("OK", null)
            .show()
    }

    private fun updateServerLabel() {
        val baseUrl = getSharedPreferences(PREFERENCES, MODE_PRIVATE)
            .getString(KEY_SERVER_URL, DEFAULT_SERVER_URL)
            .orEmpty()
        serverLabel.text = "Backend: ${baseUrl.ifBlank { "not configured" }}"
    }

    private fun setStatus(message: String) {
        statusText.text = message
        statusText.contentDescription = message
    }

    private fun text(value: String, size: Int, color: Int, bold: Boolean = false): TextView {
        return TextView(this).apply {
            text = value
            textSize = size.toFloat()
            setTextColor(color)
            if (bold) setTypeface(typeface, Typeface.BOLD)
            gravity = Gravity.START
            setLineSpacing(dp(2).toFloat(), 1f)
            importantForAccessibility = View.IMPORTANT_FOR_ACCESSIBILITY_YES
        }
    }

    private fun button(value: String): Button = Button(this).apply {
        text = value
        textSize = 15f
        isAllCaps = false
        minHeight = dp(48)
        contentDescription = value
    }

    private fun rounded(fill: Int, stroke: Int): GradientDrawable =
        GradientDrawable().apply {
            setColor(fill)
            cornerRadius = dp(10).toFloat()
            setStroke(dp(1), stroke)
        }

    private fun spacing(top: Int = 0, bottom: Int = 0): LinearLayout.LayoutParams =
        LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT).apply {
            topMargin = dp(top)
            bottomMargin = dp(bottom)
        }

    private fun dp(value: Int): Int = (value * resources.displayMetrics.density).toInt()

    companion object {
        private const val PREFERENCES = "cybershield_settings"
        private const val KEY_SERVER_URL = "server_base_url"
        private const val DEFAULT_SERVER_URL = "http://10.0.2.2:3000"
        private const val STATE_URL = "selected_url"
        private const val COLOR_BACKGROUND = 0xFF0D1425.toInt()
        private const val COLOR_SURFACE = 0xFF151F33.toInt()
        private const val COLOR_BORDER = 0xFF34445E.toInt()
        private const val COLOR_TEXT = 0xFFEDF2FA.toInt()
        private const val COLOR_MUTED = 0xFFAAB7C8.toInt()
        private const val COLOR_RED = 0xFFFF9CA5.toInt()
        private const val COLOR_BLOCKED = 0xFF3A1821.toInt()
    }
}
