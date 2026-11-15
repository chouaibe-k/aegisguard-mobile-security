package com.aegisguard.security.detector

import android.content.Context
import android.media.AudioManager
import android.media.AudioRecordingConfiguration
import android.os.Build
import android.telephony.TelephonyManager
import android.util.Log
import androidx.annotation.RequiresApi
import com.aegisguard.security.scanner.HardwareType
import com.aegisguard.security.scanner.PrivacyAccessEvent
import com.aegisguard.security.scanner.ThreatCategory
import com.aegisguard.security.scanner.ThreatItem
import com.aegisguard.security.scanner.ThreatSeverity
import java.util.concurrent.CopyOnWriteArrayList

/**
 * CallEavesdropDetector monitors real-time telephony state and intercepts unauthorized
 * audio recording sessions that initiate during incoming or outgoing calls.
 */
class CallEavesdropDetector(
    private val context: Context,
    private val onEavesdroppingDetected: (ThreatItem) -> Unit,
    private val onPrivacyEvent: (PrivacyAccessEvent) -> Unit
) {
    private val TAG = "CallEavesdropDetector"
    private val audioManager = context.getSystemService(Context.AUDIO_SERVICE) as AudioManager
    private var isCallInProgress = false
    private var recordingCallback: AudioManager.AudioRecordingCallback? = null

    // Allowed default phone app packages
    private val trustedDialerPackages = mutableSetOf(
        "com.google.android.dialer",
        "com.android.server.telecom",
        "com.samsung.android.dialer",
        "com.android.phone",
        context.packageName
    )

    fun startMonitoring() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            registerRecordingCallback()
        }
        Log.i(TAG, "Call eavesdropping & anti-wiretap shield activated")
    }

    fun stopMonitoring() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q && recordingCallback != null) {
            audioManager.unregisterAudioRecordingCallback(recordingCallback!!)
        }
    }

    fun onCallStateChanged(state: Int, incomingNumber: String?) {
        when (state) {
            TelephonyManager.CALL_STATE_OFFHOOK -> {
                isCallInProgress = true
                Log.w(TAG, "Call in progress (OFFHOOK). Initiating deep eavesdropping surveillance...")
                checkActiveRecordingSessions(isRealCall = true)
            }
            TelephonyManager.CALL_STATE_RINGING -> {
                Log.d(TAG, "Call ringing from $incomingNumber")
            }
            TelephonyManager.CALL_STATE_IDLE -> {
                isCallInProgress = false
                Log.d(TAG, "Call ended (IDLE). Resetting call privacy state.")
            }
        }
    }

    @RequiresApi(Build.VERSION_CODES.Q)
    private fun registerRecordingCallback() {
        recordingCallback = object : AudioManager.AudioRecordingCallback() {
            override fun onRecordingConfigChanged(configs: List<AudioRecordingConfiguration>?) {
                super.onRecordingConfigChanged(configs)
                configs?.forEach { config ->
                    inspectRecordingConfig(config)
                }
            }
        }
        audioManager.registerAudioRecordingCallback(recordingCallback!!, null)
    }

    @RequiresApi(Build.VERSION_CODES.Q)
    private fun inspectRecordingConfig(config: AudioRecordingConfiguration) {
        val clientAudioSource = config.clientAudioSource
        val clientPackage = config.clientPackageName ?: "Unknown Application"
        val clientUid = config.clientAudioSessionId

        val isSystemDialer = trustedDialerPackages.contains(clientPackage)

        val isWiretappingSuspect = isCallInProgress && !isSystemDialer

        Log.w(
            TAG,
            "Audio record detected: pkg=$clientPackage, source=$clientAudioSource, callActive=$isCallInProgress"
        )

        val event = PrivacyAccessEvent(
            hardwareResource = if (isCallInProgress) HardwareType.VOICE_CALL_AUDIO else HardwareType.MICROPHONE,
            packageName = clientPackage,
            appName = resolveAppName(clientPackage),
            isBackground = true,
            durationSeconds = 1,
            isAuthorized = isSystemDialer,
            riskScore = if (isWiretappingSuspect) 95 else 25
        )
        onPrivacyEvent(event)

        if (isWiretappingSuspect) {
            val threat = ThreatItem(
                title = "Call Wiretapping & Audio Snooper Detected",
                packageName = clientPackage,
                appName = resolveAppName(clientPackage),
                category = ThreatCategory.CALL_RECORDER,
                severity = ThreatSeverity.CRITICAL,
                description = "The application '$clientPackage' engaged a voice recording hook while a sensitive phone call was actively in progress without system dialer authorization.",
                indicators = listOf(
                    "Telephony State: CALL_STATE_OFFHOOK",
                    "Audio Source: $clientAudioSource",
                    "Recording Client UID: $clientUid",
                    "Unauthorized background listener"
                ),
                recommendedAction = "Immediately terminate the application, revoke RECORD_AUDIO permission, and perform a deep malware scan."
            )
            onEavesdroppingDetected(threat)
        }
    }

    private fun checkActiveRecordingSessions(isRealCall: Boolean) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
            val activeRecordings = audioManager.activeRecordingConfigurations
            for (config in activeRecordings) {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                    inspectRecordingConfig(config)
                }
            }
        }
    }

    private fun resolveAppName(packageName: String): String {
        return try {
            val pm = context.packageManager
            val appInfo = pm.getApplicationInfo(packageName, 0)
            pm.getApplicationLabel(appInfo).toString()
        } catch (e: Exception) {
            packageName
        }
    }
}
