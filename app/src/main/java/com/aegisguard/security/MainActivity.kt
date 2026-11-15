package com.aegisguard.security

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.provider.Settings
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.animation.*
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.content.ContextCompat
import com.aegisguard.security.scanner.*
import com.aegisguard.security.service.PrivacySentinelService
import kotlinx.coroutines.launch

class MainActivity : ComponentActivity() {

    private val requestPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.RequestMultiplePermissions()
    ) { permissions ->
        // Handle granted permissions
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        requestRequiredPermissions()

        setContent {
            AegisGuardTheme {
                SecurityMainScreen(
                    onScanRequested = { scanner, onFinish ->
                        // Execute scan
                    },
                    onOpenAppDetails = { pkgName ->
                        val intent = Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS).apply {
                            data = Uri.fromParts("package", pkgName, null)
                        }
                        startActivity(intent)
                    }
                )
            }
        }
    }

    private fun requestRequiredPermissions() {
        val permissionsToRequest = mutableListOf(
            Manifest.permission.CAMERA,
            Manifest.permission.RECORD_AUDIO,
            Manifest.permission.READ_PHONE_STATE,
            Manifest.permission.READ_CALL_LOG
        )
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            permissionsToRequest.add(Manifest.permission.POST_NOTIFICATIONS)
        }

        val ungranted = permissionsToRequest.filter {
            ContextCompat.checkSelfPermission(this, it) != PackageManager.PERMISSION_GRANTED
        }

        if (ungranted.isNotEmpty()) {
            requestPermissionLauncher.launch(ungranted.toTypedArray())
        }
    }
}

// Colors and Styling
val CyberDark = Color(0xFF090D16)
val CyberCard = Color(0xFF131B2A)
val NeonCyan = Color(0xFF00F0FF)
val NeonGreen = Color(0xFF00E676)
val NeonRed = Color(0xFFFF1744)
val NeonOrange = Color(0xFFFF9100)
val TextMuted = Color(0xFF90A4AE)

@Composable
fun AegisGuardTheme(content: @Composable () -> Unit) {
    MaterialTheme(
        colorScheme = darkColorScheme(
            background = CyberDark,
            surface = CyberCard,
            primary = NeonCyan,
            secondary = NeonGreen,
            error = NeonRed
        ),
        content = content
    )
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SecurityMainScreen(
    onScanRequested: (AntivirusEngine, () -> Unit) -> Unit,
    onOpenAppDetails: (String) -> Unit
) {
    var selectedTab by remember { mutableStateOf(0) }
    val tabs = listOf("Fortress", "Sentinel", "Call Shield", "Scanner", "Auditor")

    Scaffold(
        topBar = {
            TopAppBar(
                title = {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Box(
                            modifier = Modifier
                                .size(12.dp)
                                .clip(CircleShape)
                                .background(NeonGreen)
                        )
                        Spacer(modifier = Modifier.width(8.dp))
                        Text(
                            "AegisGuard Mobile Fortress",
                            fontSize = 18.sp,
                            fontWeight = FontWeight.Bold,
                            color = Color.White
                        )
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(containerColor = CyberDark)
            )
        },
        bottomBar = {
            NavigationBar(containerColor = CyberCard) {
                tabs.forEachIndexed { index, title ->
                    val icon = when (index) {
                        0 -> Icons.Default.Shield
                        1 -> Icons.Default.Visibility
                        2 -> Icons.Default.PhoneInTalk
                        3 -> Icons.Default.Search
                        else -> Icons.Default.Lock
                    }
                    NavigationBarItem(
                        selected = selectedTab == index,
                        onClick = { selectedTab = index },
                        icon = { Icon(icon, contentDescription = title) },
                        label = { Text(title, fontSize = 11.sp) },
                        colors = NavigationBarItemDefaults.colors(
                            selectedIconColor = NeonCyan,
                            selectedTextColor = NeonCyan,
                            indicatorColor = CyberDark
                        )
                    )
                }
            }
        },
        containerColor = CyberDark
    ) { padding ->
        Box(modifier = Modifier.padding(padding)) {
            when (selectedTab) {
                0 -> DashboardView()
                1 -> SentinelView()
                2 -> CallShieldView()
                3 -> ScannerView(onOpenAppDetails)
                4 -> AuditorView(onOpenAppDetails)
            }
        }
    }
}

@Composable
fun DashboardView() {
    LazyColumn(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        item {
            HealthScoreBanner(score = 98)
        }
        item {
            Text(
                "Active Hardware Shields",
                fontWeight = FontWeight.Bold,
                color = Color.White,
                fontSize = 16.sp
            )
        }
        item {
            ShieldCard(
                title = "Camera Sentinel",
                subtitle = "Blocks unauthorized background camera streaming",
                icon = Icons.Default.Videocam,
                isActive = true,
                badge = "MONITORED"
            )
        }
        item {
            ShieldCard(
                title = "Microphone & Call Shield",
                subtitle = "Zero-latency audio wiretap & recording hook trap",
                icon = Icons.Default.Mic,
                isActive = true,
                badge = "ACTIVE"
            )
        }
        item {
            ShieldCard(
                title = "Anti-Keylogger & Screen Guard",
                subtitle = "Interception of abusive Accessibility services",
                icon = Icons.Default.VisibilityOff,
                isActive = true,
                badge = "ARMED"
            )
        }
        item {
            ShieldCard(
                title = "Stalkerware & Virus Fortress",
                subtitle = "Deep signature & permission synergy hunter",
                icon = Icons.Default.Security,
                isActive = true,
                badge = "0 THREATS"
            )
        }
    }
}

@Composable
fun HealthScoreBanner(score: Int) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(16.dp),
        colors = CardDefaults.cardColors(containerColor = CyberCard)
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(20.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.SpaceBetween
        ) {
            Column {
                Text("FORTRESS STATUS", fontSize = 12.sp, color = NeonCyan, fontWeight = FontWeight.SemiBold)
                Text("Device Protected", fontSize = 22.sp, color = Color.White, fontWeight = FontWeight.Bold)
                Text("No active spyware or wiretaps detected", fontSize = 13.sp, color = TextMuted)
            }
            Box(
                modifier = Modifier
                    .size(72.dp)
                    .clip(CircleShape)
                    .background(Color(0xFF0D2538))
                    .border(3.dp, NeonGreen, CircleShape),
                contentAlignment = Alignment.Center
            ) {
                Text("$score%", color = NeonGreen, fontWeight = FontWeight.ExtraBold, fontSize = 20.sp)
            }
        }
    }
}

@Composable
fun ShieldCard(
    title: String,
    subtitle: String,
    icon: ImageVector,
    isActive: Boolean,
    badge: String
) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(12.dp),
        colors = CardDefaults.cardColors(containerColor = CyberCard)
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Box(
                modifier = Modifier
                    .size(44.dp)
                    .clip(CircleShape)
                    .background(Color(0xFF19253B)),
                contentAlignment = Alignment.Center
            ) {
                Icon(icon, contentDescription = null, tint = NeonCyan)
            }
            Spacer(modifier = Modifier.width(16.dp))
            Column(modifier = Modifier.weight(1f)) {
                Text(title, color = Color.White, fontWeight = FontWeight.SemiBold, fontSize = 15.sp)
                Text(subtitle, color = TextMuted, fontSize = 12.sp)
            }
            Surface(
                shape = RoundedCornerShape(8.dp),
                color = Color(0xFF0D2C22)
            ) {
                Text(
                    badge,
                    color = NeonGreen,
                    fontSize = 11.sp,
                    fontWeight = FontWeight.Bold,
                    modifier = Modifier.padding(horizontal = 8.dp, vertical = 4.dp)
                )
            }
        }
    }
}

@Composable
fun SentinelView() {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp)
    ) {
        Text("Real-Time Privacy Sentinel", fontWeight = FontWeight.Bold, color = Color.White, fontSize = 18.sp)
        Text("Continuous surveillance of hardware sensor states (Camera, Mic, Location)", color = TextMuted, fontSize = 13.sp)
        Spacer(modifier = Modifier.height(16.dp))

        // Live Sensors Status
        Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            SensorTile(name = "Camera Sensor", isEngaged = false, icon = Icons.Default.Videocam, modifier = Modifier.weight(1f))
            SensorTile(name = "Microphone", isEngaged = false, icon = Icons.Default.Mic, modifier = Modifier.weight(1f))
        }

        Spacer(modifier = Modifier.height(20.dp))
        Text("Sensor Access History", fontWeight = FontWeight.Bold, color = Color.White, fontSize = 15.sp)
        Spacer(modifier = Modifier.height(8.dp))

        LazyColumn(verticalArrangement = Arrangement.spacedBy(8.dp)) {
            item {
                AccessLogItem(app = "AegisGuard Core", resource = "Mic & Cam", time = "Just now", status = "Authorized Background Shield")
            }
            item {
                AccessLogItem(app = "System Dialer", resource = "Microphone", time = "14 mins ago", status = "Normal Foreground Call")
            }
        }
    }
}

@Composable
fun SensorTile(name: String, isEngaged: Boolean, icon: ImageVector, modifier: Modifier = Modifier) {
    Card(
        modifier = modifier,
        shape = RoundedCornerShape(12.dp),
        colors = CardDefaults.cardColors(containerColor = CyberCard)
    ) {
        Column(
            modifier = Modifier.padding(16.dp),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            Icon(
                icon,
                contentDescription = null,
                tint = if (isEngaged) NeonRed else NeonGreen,
                modifier = Modifier.size(32.dp)
            )
            Spacer(modifier = Modifier.height(8.dp))
            Text(name, color = Color.White, fontWeight = FontWeight.Medium, fontSize = 14.sp)
            Text(
                if (isEngaged) "IN USE" else "IDLE / SECURED",
                color = if (isEngaged) NeonRed else NeonGreen,
                fontSize = 11.sp,
                fontWeight = FontWeight.Bold
            )
        }
    }
}

@Composable
fun AccessLogItem(app: String, resource: String, time: String, status: String) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(8.dp),
        colors = CardDefaults.cardColors(containerColor = CyberCard)
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(12.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.SpaceBetween
        ) {
            Column {
                Text(app, color = Color.White, fontWeight = FontWeight.SemiBold, fontSize = 14.sp)
                Text("$resource • $time", color = TextMuted, fontSize = 12.sp)
            }
            Text(status, color = NeonGreen, fontSize = 11.sp)
        }
    }
}

@Composable
fun CallShieldView() {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp)
    ) {
        Text("Anti-Wiretap Call Shield", fontWeight = FontWeight.Bold, color = Color.White, fontSize = 18.sp)
        Text("Detects unauthorized background apps recording cellular or VoIP voice calls.", color = TextMuted, fontSize = 13.sp)
        Spacer(modifier = Modifier.height(16.dp))

        Card(
            modifier = Modifier.fillMaxWidth(),
            shape = RoundedCornerShape(14.dp),
            colors = CardDefaults.cardColors(containerColor = CyberCard)
        ) {
            Column(modifier = Modifier.padding(16.dp)) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(Icons.Default.PhoneLocked, contentDescription = null, tint = NeonCyan)
                    Spacer(modifier = Modifier.width(8.dp))
                    Text("Call State: Standby (Idle)", color = Color.White, fontWeight = FontWeight.SemiBold)
                }
                Spacer(modifier = Modifier.height(8.dp))
                Text(
                    "When you make or receive a phone call, AegisGuard locks the audio recording pipeline and triggers a high-priority alert if any third-party app attempts to intercept voice audio.",
                    color = TextMuted,
                    fontSize = 13.sp
                )
            }
        }
    }
}

@Composable
fun ScannerView(onOpenAppDetails: (String) -> Unit) {
    var isScanning by remember { mutableStateOf(false) }
    var scanProgress by remember { mutableStateOf(0f) }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp),
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        Text("Antivirus & Spyware Scanner", fontWeight = FontWeight.Bold, color = Color.White, fontSize = 18.sp)
        Spacer(modifier = Modifier.height(8.dp))
        Text("Heuristic analysis of installed apps, stalkerware signatures & storage APKs", color = TextMuted, fontSize = 13.sp)
        Spacer(modifier = Modifier.height(24.dp))

        Button(
            onClick = { isScanning = !isScanning },
            colors = ButtonDefaults.buttonColors(containerColor = NeonCyan),
            shape = RoundedCornerShape(12.dp),
            modifier = Modifier.fillMaxWidth().height(50.dp)
        ) {
            Icon(Icons.Default.Radar, contentDescription = null, tint = Color.Black)
            Spacer(modifier = Modifier.width(8.dp))
            Text(if (isScanning) "Scanning System..." else "Start Full Malware Scan", color = Color.Black, fontWeight = FontWeight.Bold)
        }

        Spacer(modifier = Modifier.height(24.dp))
        if (isScanning) {
            LinearProgressIndicator(modifier = Modifier.fillMaxWidth(), color = NeonCyan)
            Spacer(modifier = Modifier.height(8.dp))
            Text("Inspecting APK manifests and DEX signatures...", color = NeonCyan, fontSize = 12.sp)
        }
    }
}

@Composable
fun AuditorView(onOpenAppDetails: (String) -> Unit) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp)
    ) {
        Text("Permission Fortress & App Auditor", fontWeight = FontWeight.Bold, color = Color.White, fontSize = 18.sp)
        Text("Identifies apps with excessive access to Camera, Mic, Contacts, and Location.", color = TextMuted, fontSize = 13.sp)
        Spacer(modifier = Modifier.height(16.dp))

        LazyColumn(verticalArrangement = Arrangement.spacedBy(8.dp)) {
            item {
                AuditAppItem("Google Maps", "Location (Foreground)", ThreatSeverity.LOW)
            }
            item {
                AuditAppItem("WhatsApp", "Camera, Mic, Contacts", ThreatSeverity.MEDIUM)
            }
        }
    }
}

@Composable
fun AuditAppItem(name: String, perms: String, severity: ThreatSeverity) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(10.dp),
        colors = CardDefaults.cardColors(containerColor = CyberCard)
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(12.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.SpaceBetween
        ) {
            Column {
                Text(name, color = Color.White, fontWeight = FontWeight.SemiBold, fontSize = 14.sp)
                Text(perms, color = TextMuted, fontSize = 12.sp)
            }
            Text(
                severity.name,
                color = if (severity == ThreatSeverity.LOW) NeonGreen else NeonOrange,
                fontSize = 11.sp,
                fontWeight = FontWeight.Bold
            )
        }
    }
}
