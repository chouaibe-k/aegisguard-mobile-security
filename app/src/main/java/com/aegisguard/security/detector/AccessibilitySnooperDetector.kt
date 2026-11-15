package com.aegisguard.security.detector

import android.accessibilityservice.AccessibilityServiceInfo
import android.content.Context
import android.content.pm.PackageManager
import android.view.accessibility.AccessibilityManager
import com.aegisguard.security.scanner.ThreatCategory
import com.aegisguard.security.scanner.ThreatItem
import com.aegisguard.security.scanner.ThreatSeverity

/**
 * AccessibilitySnooperDetector audits enabled accessibility services.
 * Spyware and stalkerware heavily exploit Accessibility APIs to read screen contents,
 * capture typed passwords (keylogging), intercept 2FA codes, and silently grant themselves permissions.
 */
class AccessibilitySnooperDetector(private val context: Context) {

    // Known benign accessibility services (screen readers, password managers, system services)
    private val trustedAccessibilityPackages = setOf(
        "com.google.android.marvin.talkback",
        "com.android.switchaccess",
        "com.samsung.accessibility",
        "com.google.android.accessibility.suite"
    )

    fun scanEnabledAccessibilityServices(): List<ThreatItem> {
        val threats = mutableListOf<ThreatItem>()
        val am = context.getSystemService(Context.ACCESSIBILITY_SERVICE) as? AccessibilityManager ?: return threats
        val pm = context.packageManager

        val enabledServices = am.getEnabledAccessibilityServiceList(AccessibilityServiceInfo.FEEDBACK_ALL_MASK)

        for (service in enabledServices) {
            val resolveInfo = service.resolveInfo ?: continue
            val packageName = resolveInfo.serviceInfo.packageName
            val appLabel = resolveInfo.serviceInfo.loadLabel(pm).toString()

            if (trustedAccessibilityPackages.contains(packageName)) {
                continue
            }

            val capabilities = service.capabilities
            val canRetrieveWindowContent = (capabilities and AccessibilityServiceInfo.CAPABILITY_CAN_RETRIEVE_WINDOW_CONTENT) != 0
            val canRequestFilterKeyEvents = (capabilities and AccessibilityServiceInfo.CAPABILITY_CAN_REQUEST_FILTER_KEY_EVENTS) != 0
            val canPerformGestures = (capabilities and AccessibilityServiceInfo.CAPABILITY_CAN_PERFORM_GESTURES) != 0

            val indicators = mutableListOf<String>()
            var severity = ThreatSeverity.MEDIUM

            if (canRetrieveWindowContent) {
                indicators.add("Can read entire screen text, messages, and banking data (CAPABILITY_CAN_RETRIEVE_WINDOW_CONTENT)")
                severity = ThreatSeverity.HIGH
            }
            if (canRequestFilterKeyEvents) {
                indicators.add("Can intercept raw keyboard input and key events (CAPABILITY_CAN_REQUEST_FILTER_KEY_EVENTS / Keylogger)")
                severity = ThreatSeverity.CRITICAL
            }
            if (canPerformGestures) {
                indicators.add("Can inject automatic clicks and accept permission dialogs silently (CAPABILITY_CAN_PERFORM_GESTURES)")
            }

            // If an untrusted app has keylogging or window content access, flag it
            if (canRetrieveWindowContent || canRequestFilterKeyEvents) {
                threats.add(
                    ThreatItem(
                        title = if (canRequestFilterKeyEvents) "Active Keylogger / Screen Snooper Detected" else "High-Risk Screen Reading Service",
                        packageName = packageName,
                        appName = appLabel,
                        category = ThreatCategory.KEYLOGGER_ACCESSIBILITY,
                        severity = severity,
                        description = "The application '$appLabel' has been granted Accessibility privileges allowing it to record typed keystrokes and spy on on-screen activities across all apps.",
                        indicators = indicators,
                        recommendedAction = "Disable Accessibility Service for '$appLabel' in Android Settings > Accessibility immediately."
                    )
                )
            }
        }

        return threats
    }
}
