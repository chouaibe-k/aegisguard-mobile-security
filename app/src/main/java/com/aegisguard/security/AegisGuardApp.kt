package com.aegisguard.security

import android.app.Application
import com.aegisguard.security.service.PrivacySentinelService

class AegisGuardApp : Application() {
    override fun onCreate() {
        super.onCreate()
        // Initialize background protection sentinel
        PrivacySentinelService.startService(this)
    }
}
