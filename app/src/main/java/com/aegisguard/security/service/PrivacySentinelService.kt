package com.aegisguard.security.service

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.hardware.camera2.CameraManager
import android.media.AudioManager
import android.media.AudioRecordingConfiguration
import android.os.Build
import android.os.IBinder
import android.util.Log
import androidx.core.app.NotificationCompat
import com.aegisguard.security.MainActivity
import com.aegisguard.security.R
import com.aegisguard.security.detector.CallEavesdropDetector
import com.aegisguard.security.scanner.HardwareType
import com.aegisguard.security.scanner.PrivacyAccessEvent
import com.aegisguard.security.scanner.ThreatItem
import com.aegisguard.security.scanner.ThreatSeverity
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch

/**
 * PrivacySentinelService runs continuously as an Android Foreground Service,
 * utilizing CameraManager.AvailabilityCallback and AudioManager.AudioRecordingCallback
 * to provide zero-latency detection of unauthorized camera and microphone access.
 */
class PrivacySentinelService : Service() {

    private val TAG = "PrivacySentinelService"
    private val CHANNEL_ID = "aegis_privacy_sentinel_channel"
    private val ALERT_CHANNEL_ID = "aegis_threat_alert_channel"
    private val NOTIFICATION_ID = 1001

    private val serviceScope = CoroutineScope(Dispatchers.Default)

    private lateinit var cameraManager: CameraManager
    private lateinit var audioManager: AudioManager
    private lateinit var callEavesdropDetector: CallEavesdropDetector

    private var cameraCallback: CameraManager.AvailabilityCallback? = null
    private var audioRecordingCallback: AudioManager.AudioRecordingCallback? = null

    companion object {
        var instance: PrivacySentinelService? = null
            private set

        private val _privacyEvents = MutableSharedFlow<PrivacyAccessEvent>(replay = 50)
        val privacyEvents = _privacyEvents.asSharedFlow()

        private val _detectedThreats = MutableStateFlow<List<ThreatItem>>(emptyList())
        val detectedThreats = _detectedThreats.asStateFlow()

        private val _isCameraInUse = MutableStateFlow(false)
        val isCameraInUse = _isCameraInUse.asStateFlow()

        private val _isMicInUse = MutableStateFlow(false)
        val isMicInUse = _isMicInUse.asStateFlow()

        fun startService(context: Context) {
            val intent = Intent(context, PrivacySentinelService::class.java)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                context.startForegroundService(intent)
            } else {
                context.startService(intent)
            }
        }

        fun stopService(context: Context) {
            val intent = Intent(context, PrivacySentinelService::class.java)
            context.stopService(intent)
        }
    }

    override fun onCreate() {
        super.onCreate()
        instance = this
        cameraManager = getSystemService(Context.CAMERA_SERVICE) as CameraManager
        audioManager = getSystemService(Context.AUDIO_SERVICE) as AudioManager

        createNotificationChannels()
        startForeground(NOTIFICATION_ID, buildSentinelNotification("AegisGuard Privacy Sentinel Active", "Shielding Camera, Mic & Voice Calls"))

        setupCallDetector()
        setupCameraSentinel()
        setupAudioSentinel()

        Log.i(TAG, "PrivacySentinelService initialized and active.")
    }

    private fun setupCallDetector() {
        callEavesdropDetector = CallEavesdropDetector(
            context = this,
            onEavesdroppingDetected = { threat ->
                addThreat(threat)
                triggerThreatAlertNotification(threat)
            },
            onPrivacyEvent = { event ->
                recordPrivacyEvent(event)
            }
        )
        callEavesdropDetector.startMonitoring()
    }

    private fun setupCameraSentinel() {
        cameraCallback = object : CameraManager.AvailabilityCallback() {
            override fun onCameraUnavailable(cameraId: String) {
                super.onCameraUnavailable(cameraId)
                _isCameraInUse.value = true
                Log.w(TAG, "Camera $cameraId is now IN USE / UNAVAILABLE")

                val event = PrivacyAccessEvent(
                    hardwareResource = HardwareType.CAMERA,
                    packageName = "Active Sensor Client",
                    appName = "Camera Hardware Access",
                    isBackground = true,
                    durationSeconds = 0,
                    isAuthorized = false,
                    riskScore = 70
                )
                recordPrivacyEvent(event)
                updateSentinelNotification("Camera In Use", "AegisGuard detected camera sensor activation")
            }

            override fun onCameraAvailable(cameraId: String) {
                super.onCameraAvailable(cameraId)
                _isCameraInUse.value = false
                Log.i(TAG, "Camera $cameraId is now AVAILABLE (closed)")
                updateSentinelNotification("AegisGuard Shield Active", "Camera, Mic & Calls protected")
            }
        }
        cameraManager.registerAvailabilityCallback(cameraCallback!!, null)
    }

    private fun setupAudioSentinel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            audioRecordingCallback = object : AudioManager.AudioRecordingCallback() {
                override fun onRecordingConfigChanged(configs: List<AudioRecordingConfiguration>?) {
                    super.onRecordingConfigChanged(configs)
                    val isRecording = !(configs.isNullOrEmpty())
                    _isMicInUse.value = isRecording

                    if (isRecording) {
                        configs?.forEach { config ->
                            val clientPkg = try {
                                val method = config.javaClass.getMethod("getClientPackageName")
                                method.invoke(config) as? String
                            } catch (e: Exception) {
                                null
                            } ?: try {
                                val uidMethod = config.javaClass.getMethod("getClientUid")
                                val uid = uidMethod.invoke(config) as? Int ?: 0
                                packageManager.getNameForUid(uid)
                            } catch (e: Exception) {
                                null
                            } ?: "Audio Client"
                            Log.w(TAG, "Microphone actively recording by: $clientPkg")

                            val event = PrivacyAccessEvent(
                                hardwareResource = HardwareType.MICROPHONE,
                                packageName = clientPkg,
                                appName = clientPkg,
                                isBackground = true,
                                durationSeconds = 1,
                                isAuthorized = false,
                                riskScore = 65
                            )
                            recordPrivacyEvent(event)
                        }
                        updateSentinelNotification("Microphone In Use", "Audio recording actively monitored")
                    } else {
                        updateSentinelNotification("AegisGuard Shield Active", "Camera, Mic & Calls protected")
                    }
                }
            }
            audioManager.registerAudioRecordingCallback(audioRecordingCallback!!, null)
        }
    }

    fun handleCallStateChange(state: Int, incomingNumber: String?) {
        callEavesdropDetector.onCallStateChanged(state, incomingNumber)
    }

    private fun recordPrivacyEvent(event: PrivacyAccessEvent) {
        serviceScope.launch {
            _privacyEvents.emit(event)
        }
    }

    fun addThreat(threat: ThreatItem) {
        serviceScope.launch {
            val current = _detectedThreats.value.toMutableList()
            if (current.none { it.packageName == threat.packageName && it.category == threat.category }) {
                current.add(0, threat)
                _detectedThreats.value = current
            }
        }
    }

    private fun createNotificationChannels() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val notificationManager = getSystemService(NotificationManager::class.java)

            val sentinelChannel = NotificationChannel(
                CHANNEL_ID,
                "AegisGuard Sentinel Status",
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = "Shows real-time status of camera, mic, and call protection"
            }

            val alertChannel = NotificationChannel(
                ALERT_CHANNEL_ID,
                "AegisGuard Security Threat Alerts",
                NotificationManager.IMPORTANCE_HIGH
            ).apply {
                description = "Instant alerts for unauthorized camera, mic, or wiretapping access"
                enableVibration(true)
            }

            notificationManager.createNotificationChannel(sentinelChannel)
            notificationManager.createNotificationChannel(alertChannel)
        }
    }

    private fun buildSentinelNotification(title: String, text: String): Notification {
        val pendingIntent = PendingIntent.getActivity(
            this,
            0,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE
        )

        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle(title)
            .setContentText(text)
            .setSmallIcon(android.R.drawable.ic_lock_idle_lock)
            .setContentIntent(pendingIntent)
            .setOngoing(true)
            .build()
    }

    private fun updateSentinelNotification(title: String, text: String) {
        val notificationManager = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        notificationManager.notify(NOTIFICATION_ID, buildSentinelNotification(title, text))
    }

    private fun triggerThreatAlertNotification(threat: ThreatItem) {
        val notificationManager = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        val pendingIntent = PendingIntent.getActivity(
            this,
            threat.id.hashCode(),
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE
        )

        val alertNotification = NotificationCompat.Builder(this, ALERT_CHANNEL_ID)
            .setContentTitle("🚨 ${threat.title}")
            .setContentText("${threat.appName}: ${threat.description}")
            .setSmallIcon(android.R.drawable.stat_notify_error)
            .setPriority(NotificationCompat.PRIORITY_MAX)
            .setCategory(NotificationCompat.CATEGORY_ALARM)
            .setAutoCancel(true)
            .setContentIntent(pendingIntent)
            .addAction(android.R.drawable.ic_delete, "Neutralize Threat", pendingIntent)
            .build()

        notificationManager.notify(threat.id.hashCode(), alertNotification)
    }

    override fun onDestroy() {
        super.onDestroy()
        if (cameraCallback != null) {
            cameraManager.unregisterAvailabilityCallback(cameraCallback!!)
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q && audioRecordingCallback != null) {
            audioManager.unregisterAudioRecordingCallback(audioRecordingCallback!!)
        }
        callEavesdropDetector.stopMonitoring()
        instance = null
        Log.i(TAG, "PrivacySentinelService destroyed.")
    }

    override fun onBind(intent: Intent?): IBinder? = null
}
