package com.aegisguard.security.scanner

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.os.Build
import android.os.Environment
import android.util.Log
import com.aegisguard.security.detector.AccessibilitySnooperDetector
import com.aegisguard.security.detector.HiddenAppDetector
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File

/**
 * AntivirusEngine performs deep multi-vector heuristic analysis and signature detection:
 * 1. Known Stalkerware & Mobile Trojan Signature Matching
 * 2. High-Risk Dangerous Permission Synergies (Mic + Cam + Calls + Background Boot)
 * 3. Accessibility & Keylogger Surveillance Detection
 * 4. Stealth & Ghost Apps (No Launcher Activity)
 * 5. Download & Storage Malicious APK Scanner
 */
class AntivirusEngine(private val context: Context) {

    private val TAG = "AntivirusEngine"
    private val accessibilityDetector = AccessibilitySnooperDetector(context)
    private val hiddenAppDetector = HiddenAppDetector(context)

    // Known stalkerware, spyware, and trojan package identifiers & signature patterns
    private val knownMalwareSignatures = mapOf(
        "com.mspy.android" to Pair("mSpy Commercial Stalkerware", "Active surveillance suite recording mic, calls, GPS, and keystrokes."),
        "com.flexispy" to Pair("FlexiSPY Trojan", "Extreme stalkerware capable of live call listening, ambient mic recording, and camera snapshots."),
        "org.cerberus.app" to Pair("Cerberus Stealth Tracker", "Remote surveillance tool with stealth SMS commands and audio interception."),
        "com.hoverwatch" to Pair("Hoverwatch Invisible Tracker", "Hidden mobile monitor recording call audio, WhatsApp, and front camera selfies."),
        "com.spyera" to Pair("Spyera Phone Spy", "Stealth wiretapping package capable of bugging ambient surroundings and eavesdropping on VoIP/cellular calls."),
        "com.spyhide.sys" to Pair("SpyHide Stalkerware", "Disguised background tracking tool exfiltrating audio recordings and call logs."),
        "com.finspy.mobile" to Pair("FinFisher / FinSpy", "Nation-state grade mobile surveillance malware targeting calls, audio, and encrypted chats."),
        "org.pegasus.surveillance" to Pair("Pegasus Spyware Family", "Zero-click exploit framework capable of total device takeover, mic eavesdropping, and camera access."),
        "com.anatsa.dropper" to Pair("Anatsa Banking Trojan", "Overlay and accessibility abuser stealing credentials and intercepting 2FA."),
        "com.sharkbot.stealer" to Pair("SharkBot Malware", "Malicious accessibility malware injecting fake login screens and recording keystrokes."),
        "com.flubot.sms" to Pair("FluBot / Cabassous", "Aggressive SMS worm and spyware capturing contacts and credit card entries.")
    )

    // Trusted package prefixes that should not be marked as malware
    private val trustedVendors = listOf(
        "com.google.android.",
        "com.android.",
        "com.samsung.",
        "com.aegisguard."
    )

    data class ScanProgress(
        val currentScannedCount: Int,
        val totalCount: Int,
        val currentFileNameOrPackage: String,
        val threatsFound: Int
    )

    suspend fun performDeepScan(
        onProgress: (ScanProgress) -> Unit = {}
    ): Pair<List<ThreatItem>, List<AppPermissionAudit>> = withContext(Dispatchers.IO) {
        val pm = context.packageManager
        val threats = mutableListOf<ThreatItem>()
        val audits = mutableListOf<AppPermissionAudit>()

        val installedPackages = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            pm.getInstalledPackages(PackageManager.PackageInfoFlags.of(PackageManager.GET_PERMISSIONS.toLong()))
        } else {
            @Suppress("DEPRECATION")
            pm.getInstalledPackages(PackageManager.GET_PERMISSIONS)
        }

        val total = installedPackages.size + 20 // Add buffer for file storage scanner

        // 1. Accessibility & Keylogger Audit
        onProgress(ScanProgress(1, total, "Scanning Active Accessibility Services...", threats.size))
        threats.addAll(accessibilityDetector.scanEnabledAccessibilityServices())

        // 2. Hidden & Ghost App Audit
        onProgress(ScanProgress(3, total, "Detecting Hidden Stalkerware & Device Admins...", threats.size))
        threats.addAll(hiddenAppDetector.scanHiddenAndAdminApps())

        // 3. Package by package deep heuristic audit
        var index = 5
        for (pkgInfo in installedPackages) {
            index++
            val pkgName = pkgInfo.packageName
            val appLabel = pkgInfo.applicationInfo?.loadLabel(pm)?.toString() ?: pkgName
            onProgress(ScanProgress(index, total, "Inspecting $appLabel ($pkgName)", threats.size))

            // Signature match
            val signatureMatch = knownMalwareSignatures[pkgName]
            if (signatureMatch != null) {
                threats.add(
                    ThreatItem(
                        title = signatureMatch.first,
                        packageName = pkgName,
                        appName = appLabel,
                        category = ThreatCategory.STALKERWARE_TROJAN,
                        severity = ThreatSeverity.CRITICAL,
                        description = signatureMatch.second,
                        indicators = listOf(
                            "Matched Known Malware Signature: ${signatureMatch.first}",
                            "Critical threat to voice, camera, and personal data",
                            "Package: $pkgName"
                        ),
                        recommendedAction = "Immediately uninstall this malicious stalkerware package."
                    )
                )
            }

            // Permission Synergy Heuristics
            val audit = analyzePackagePermissions(pkgInfo, pm)
            audits.add(audit)

            if (audit.riskLevel == ThreatSeverity.CRITICAL || audit.riskLevel == ThreatSeverity.HIGH) {
                // If not already detected by signature
                if (threats.none { it.packageName == pkgName }) {
                    threats.add(
                        ThreatItem(
                            title = "High-Risk Surveillance Permission Synergy",
                            packageName = pkgName,
                            appName = appLabel,
                            category = ThreatCategory.MALICIOUS_PERMISSION_SYNERGY,
                            severity = audit.riskLevel,
                            description = "Application '$appLabel' possesses an alarming combination of permissions capable of silent camera usage, microphone tapping, and call recording.",
                            indicators = audit.riskReasons,
                            recommendedAction = "Revoke Camera, Microphone, and Call permissions in Android Settings, or uninstall if untrusted."
                        )
                    )
                }
            }
        }

        // 4. Storage & Download directory scan for malicious APKs
        onProgress(ScanProgress(total - 10, total, "Scanning Storage & Downloads for Malicious APKs...", threats.size))
        scanStorageForMaliciousApks(pm, threats)

        onProgress(ScanProgress(total, total, "Scan Complete", threats.size))
        Pair(threats, audits.sortedByDescending { it.riskScore })
    }

    private fun analyzePackagePermissions(pkgInfo: PackageInfo, pm: PackageManager): AppPermissionAudit {
        val appInfo = pkgInfo.applicationInfo ?: return createDefaultAudit(pkgInfo.packageName)
        val isSystem = (appInfo.flags and ApplicationInfo.FLAG_SYSTEM) != 0 ||
                (appInfo.flags and ApplicationInfo.FLAG_UPDATED_SYSTEM_APP) != 0

        val requestedPermissions = pkgInfo.requestedPermissions?.toSet() ?: emptySet()

        val hasCamera = requestedPermissions.contains("android.permission.CAMERA")
        val hasMicrophone = requestedPermissions.contains("android.permission.RECORD_AUDIO")
        val hasCallLog = requestedPermissions.contains("android.permission.READ_CALL_LOG") ||
                requestedPermissions.contains("android.permission.PROCESS_OUTGOING_CALLS") ||
                requestedPermissions.contains("android.permission.READ_PHONE_STATE")
        val hasOverlay = requestedPermissions.contains("android.permission.SYSTEM_ALERT_WINDOW")
        val hasLocation = requestedPermissions.contains("android.permission.ACCESS_FINE_LOCATION")
        val hasBoot = requestedPermissions.contains("android.permission.RECEIVE_BOOT_COMPLETED")

        var riskScore = 0
        val reasons = mutableListOf<String>()

        if (!isSystem) {
            if (hasCamera) {
                riskScore += 25
                reasons.add("Access to Camera (can capture photos/video)")
            }
            if (hasMicrophone) {
                riskScore += 30
                reasons.add("Access to Microphone (can record ambient audio)")
            }
            if (hasCallLog) {
                riskScore += 20
                reasons.add("Access to Phone Calls & Call State (potential eavesdropping)")
            }
            if (hasLocation) {
                riskScore += 15
                reasons.add("Access to Precise GPS Location")
            }
            if (hasOverlay) {
                riskScore += 20
                reasons.add("Can draw over other apps (potential phishing/overlay attack)")
            }
            if (hasBoot) {
                riskScore += 10
                reasons.add("Starts automatically at device reboot")
            }

            // Dangerous synergy multiplier: Mic + Cam + Call + Boot in a 3rd party app
            if (hasMicrophone && hasCamera && hasCallLog && hasBoot) {
                riskScore += 30
                reasons.add("CRITICAL SYNERGY: Holds Mic + Camera + Call Log + Auto-boot without user interaction")
            }
        }

        val riskLevel = when {
            riskScore >= 75 -> ThreatSeverity.CRITICAL
            riskScore >= 50 -> ThreatSeverity.HIGH
            riskScore >= 25 -> ThreatSeverity.MEDIUM
            else -> ThreatSeverity.LOW
        }

        return AppPermissionAudit(
            packageName = pkgInfo.packageName,
            appName = appInfo.loadLabel(pm).toString(),
            isSystemApp = isSystem,
            hasCamera = hasCamera,
            hasMicrophone = hasMicrophone,
            hasCallLog = hasCallLog,
            hasAccessibility = false,
            hasDeviceAdmin = false,
            hasOverlay = hasOverlay,
            hasLocation = hasLocation,
            riskScore = riskScore.coerceAtMost(100),
            riskLevel = riskLevel,
            riskReasons = reasons
        )
    }

    private fun scanStorageForMaliciousApks(pm: PackageManager, threats: MutableList<ThreatItem>) {
        try {
            val downloadDir = Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS)
            if (downloadDir.exists() && downloadDir.isDirectory) {
                val apkFiles = downloadDir.listFiles { file -> file.extension.equals("apk", ignoreCase = true) }
                apkFiles?.forEach { apkFile ->
                    val archiveInfo = pm.getPackageArchiveInfo(apkFile.absolutePath, PackageManager.GET_PERMISSIONS)
                    if (archiveInfo != null) {
                        val pkgName = archiveInfo.packageName
                        if (knownMalwareSignatures.containsKey(pkgName)) {
                            threats.add(
                                ThreatItem(
                                    title = "Sideloaded Malicious APK in Downloads",
                                    packageName = pkgName,
                                    appName = apkFile.name,
                                    category = ThreatCategory.STALKERWARE_TROJAN,
                                    severity = ThreatSeverity.CRITICAL,
                                    description = "A malicious APK matching known spyware signature was found in Downloads folder: ${apkFile.name}",
                                    indicators = listOf(
                                        "File Path: ${apkFile.absolutePath}",
                                        "Matched Malware Package: $pkgName"
                                    ),
                                    recommendedAction = "Delete the APK file immediately to prevent infection."
                                )
                            )
                        }
                    }
                }
            }
        } catch (e: Exception) {
            Log.e(TAG, "Storage scan exception", e)
        }
    }

    private fun createDefaultAudit(pkgName: String): AppPermissionAudit {
        return AppPermissionAudit(
            packageName = pkgName,
            appName = pkgName,
            isSystemApp = false,
            hasCamera = false,
            hasMicrophone = false,
            hasCallLog = false,
            hasAccessibility = false,
            hasDeviceAdmin = false,
            hasOverlay = false,
            hasLocation = false,
            riskScore = 0,
            riskLevel = ThreatSeverity.LOW,
            riskReasons = emptyList()
        )
    }
}
