package com.aegisguard.security.detector

import android.app.admin.DevicePolicyManager
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import com.aegisguard.security.scanner.ThreatCategory
import com.aegisguard.security.scanner.ThreatItem
import com.aegisguard.security.scanner.ThreatSeverity

/**
 * HiddenAppDetector identifies stealth apps that hide their launcher icons from the app drawer,
 * disguised fake system applications, and apps granted Device Administrator privileges.
 */
class HiddenAppDetector(private val context: Context) {

    private val suspiciousDisguiseNames = listOf(
        "system update", "google service", "device health", "android service",
        "battery optimizer", "wifi core", "system core service", "sync manager"
    )

    fun scanHiddenAndAdminApps(): List<ThreatItem> {
        val threats = mutableListOf<ThreatItem>()
        val pm = context.packageManager
        val dpm = context.getSystemService(Context.DEVICE_POLICY_SERVICE) as? DevicePolicyManager

        // 1. Check Device Administrator apps
        val activeAdmins: List<ComponentName>? = dpm?.activeAdmins
        activeAdmins?.forEach { admin ->
            val pkg = admin.packageName
            if (pkg != context.packageName && !isLegitimateSystemPackage(pkg)) {
                threats.add(
                    ThreatItem(
                        title = "Suspicious Device Administrator Rights",
                        packageName = pkg,
                        appName = getAppName(pkg, pm),
                        category = ThreatCategory.GHOST_HIDDEN_APP,
                        severity = ThreatSeverity.HIGH,
                        description = "This application holds Device Admin privileges, preventing regular uninstallation and giving it remote control capabilities.",
                        indicators = listOf(
                            "Device Administrator Active: ${admin.className}",
                            "Can lock device or wipe data",
                            "Prevents standard Android uninstallation"
                        ),
                        recommendedAction = "Revoke Device Admin privilege in Settings > Security > Device Administrators, then uninstall."
                    )
                )
            }
        }

        // 2. Check for Ghost apps (Non-system apps without a launcher activity)
        val launcherIntent = Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_LAUNCHER)
        val launcherApps = pm.queryIntentActivities(launcherIntent, 0).map { it.activityInfo.packageName }.toSet()

        val installedApps = pm.getInstalledApplications(PackageManager.GET_META_DATA)
        for (app in installedApps) {
            val pkg = app.packageName
            val isSystem = (app.flags and ApplicationInfo.FLAG_SYSTEM) != 0 || (app.flags and ApplicationInfo.FLAG_UPDATED_SYSTEM_APP) != 0

            if (!isSystem && pkg != context.packageName) {
                val hasLauncherIcon = launcherApps.contains(pkg)
                val label = pm.getApplicationLabel(app).toString().lowercase()

                // If app has no launcher activity but requests sensitive background permissions
                if (!hasLauncherIcon) {
                    val isDisguised = suspiciousDisguiseNames.any { label.contains(it) }
                    
                    threats.add(
                        ThreatItem(
                            title = if (isDisguised) "Stealth Disguised Stalkerware Detected" else "Hidden Background Ghost App",
                            packageName = pkg,
                            appName = pm.getApplicationLabel(app).toString(),
                            category = ThreatCategory.GHOST_HIDDEN_APP,
                            severity = if (isDisguised) ThreatSeverity.CRITICAL else ThreatSeverity.HIGH,
                            description = "Application is running completely hidden from the Android App Drawer without an icon, which is a classic stalkerware & trojan tactic.",
                            indicators = listOf(
                                "No Launcher Activity found (Stealth Mode)",
                                if (isDisguised) "Deceptive System Name Disguise: '$label'" else "Hidden background daemon",
                                "Package: $pkg"
                            ),
                            recommendedAction = "Inspect app details in Android Settings > Apps and uninstall immediately."
                        )
                    )
                }
            }
        }

        return threats
    }

    private fun isLegitimateSystemPackage(packageName: String): Boolean {
        return packageName.startsWith("com.google.android.") ||
                packageName.startsWith("com.android.") ||
                packageName.startsWith("com.samsung.")
    }

    private fun getAppName(packageName: String, pm: PackageManager): String {
        return try {
            val info = pm.getApplicationInfo(packageName, 0)
            pm.getApplicationLabel(info).toString()
        } catch (e: Exception) {
            packageName
        }
    }
}
