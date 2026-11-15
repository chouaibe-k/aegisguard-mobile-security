package com.aegisguard.security.scanner

import java.util.UUID

enum class ThreatSeverity {
    CRITICAL,
    HIGH,
    MEDIUM,
    LOW,
    INFO
}

enum class ThreatCategory {
    CAMERA_SPY,
    AUDIO_WIRETAP,
    CALL_RECORDER,
    KEYLOGGER_ACCESSIBILITY,
    STALKERWARE_TROJAN,
    GHOST_HIDDEN_APP,
    UNAUTHORIZED_EXFILTRATION,
    MALICIOUS_PERMISSION_SYNERGY
}

data class ThreatItem(
    val id: String = UUID.randomUUID().toString(),
    val title: String,
    val packageName: String,
    val appName: String,
    val category: ThreatCategory,
    val severity: ThreatSeverity,
    val description: String,
    val indicators: List<String>,
    val detectedAt: Long = System.currentTimeMillis(),
    val isResolved: Boolean = false,
    val recommendedAction: String
)

data class PrivacyAccessEvent(
    val id: String = UUID.randomUUID().toString(),
    val timestamp: Long = System.currentTimeMillis(),
    val hardwareResource: HardwareType,
    val packageName: String,
    val appName: String,
    val isBackground: Boolean,
    val durationSeconds: Long = 0,
    val isAuthorized: Boolean = false,
    val riskScore: Int = 0 // 0 to 100
)

enum class HardwareType {
    CAMERA,
    MICROPHONE,
    VOICE_CALL_AUDIO,
    SCREEN_RECORDING,
    FINE_LOCATION
}

data class AppPermissionAudit(
    val packageName: String,
    val appName: String,
    val iconRes: Int? = null,
    val isSystemApp: Boolean,
    val hasCamera: Boolean,
    val hasMicrophone: Boolean,
    val hasCallLog: Boolean,
    val hasAccessibility: Boolean,
    val hasDeviceAdmin: Boolean,
    val hasOverlay: Boolean,
    val hasLocation: Boolean,
    val riskScore: Int, // 0 to 100
    val riskLevel: ThreatSeverity,
    val riskReasons: List<String>
)

data class SecurityDashboardState(
    val overallHealthScore: Int = 98,
    val isSentinelActive: Boolean = true,
    val isCameraShieldActive: Boolean = true,
    val isMicShieldActive: Boolean = true,
    val isCallWiretapShieldActive: Boolean = true,
    val isAntiKeyloggerActive: Boolean = true,
    val totalThreatsDetected: Int = 0,
    val resolvedThreatsCount: Int = 0,
    val totalAppsAudited: Int = 84,
    val activeMicrophoneApp: String? = null,
    val activeCameraApp: String? = null,
    val isCallActive: Boolean = false,
    val isCallUnderEavesdropping: Boolean = false,
    val lastScanTimestamp: Long = System.currentTimeMillis()
)
