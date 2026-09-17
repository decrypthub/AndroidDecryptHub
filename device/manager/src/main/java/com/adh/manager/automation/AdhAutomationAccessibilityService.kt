package com.adh.manager.automation

import android.accessibilityservice.AccessibilityService
import android.app.KeyguardManager
import android.accessibilityservice.AccessibilityServiceInfo
import android.accessibilityservice.GestureDescription
import android.content.Intent
import android.graphics.Bitmap
import android.graphics.Path
import android.graphics.Rect
import android.os.Build
import android.os.Bundle
import android.os.PowerManager
import android.os.SystemClock
import android.provider.Settings
import android.util.Base64
import android.util.Log
import android.view.Display
import android.view.WindowManager
import android.view.accessibility.AccessibilityEvent
import android.view.accessibility.AccessibilityNodeInfo
import com.adh.core.AdhProtocol
import com.adh.core.PackageControl
import com.adh.manager.ipc.DaemonBinderProvider
import org.json.JSONArray
import com.adh.manager.notify.AdhNotificationListener
import org.json.JSONObject
import java.io.ByteArrayOutputStream
import java.security.MessageDigest
import java.util.ArrayDeque
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import kotlin.math.max
import kotlin.math.min

/**
 * Optional, user-enabled accessibility executor for AI phone control.
 *
 * It exposes no network service. The only transport is the narrow outbound bridge in
 * [AutomationBridgeClient], and every action follows the same policy: active package must be
 * explicitly allowed, node refs are snapshot-bound, and coordinate actions use normalized input.
 */
class AdhAutomationAccessibilityService : AccessibilityService() {
    private val executor = Executors.newSingleThreadExecutor { runnable ->
        Thread(runnable, "adh-accessibility-capture").apply { isDaemon = true }
    }
    private val snapshots = ConcurrentHashMap<String, Snapshot>()
    private val snapshotOrder = ArrayDeque<String>()
    private var snapshotSeq = 0

    @Volatile private var bridge: AutomationBridgeClient? = null

    @Volatile private var lastActivePackage: String = ""

    @Volatile private var lastActivity: String = ""

    override fun onServiceConnected() {
        super.onServiceConnected()
        serviceInfo = serviceInfo?.apply {
            flags = flags or AccessibilityServiceInfo.FLAG_REPORT_VIEW_IDS or
                AccessibilityServiceInfo.FLAG_RETRIEVE_INTERACTIVE_WINDOWS
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) notificationTimeout = 100
        }
        val deviceId = Settings.Secure.getString(contentResolver, Settings.Secure.ANDROID_ID)
            ?.takeIf { it.isNotBlank() }
            ?: Build.FINGERPRINT
        bridge?.stop()
        // Remember the host's LAN addresses across service restarts: after one adb-reverse session
        // the phone can reconnect over Wi-Fi without the cable.
        val memory = getSharedPreferences(BRIDGE_PREFS, MODE_PRIVATE)
        val remembered = (memory.getStringSet(BRIDGE_LAN_HOSTS, emptySet()) ?: emptySet()).toList()
        bridge = AutomationBridgeClient(
            deviceId,
            Build.MODEL,
            Build.VERSION.SDK_INT,
            ::handleCommand,
            rememberedHosts = remembered,
            onLanHosts = { hosts ->
                memory.edit().putStringSet(BRIDGE_LAN_HOSTS, hosts.take(4).toSet()).apply()
            },
        ).also { it.start() }
        Log.i(TAG, "automation accessibility service connected")
    }

    override fun onAccessibilityEvent(event: AccessibilityEvent?) {
        event?.packageName?.toString()?.takeIf { it.isNotBlank() }?.let { lastActivePackage = it }
        if (event?.eventType == AccessibilityEvent.TYPE_WINDOW_STATE_CHANGED) {
            event.className?.toString()?.takeIf { it.isNotBlank() }?.let { lastActivity = it }
        }
    }

    override fun onInterrupt() = Unit

    override fun onDestroy() {
        bridge?.stop()
        bridge = null
        snapshots.clear()
        snapshotOrder.clear()
        executor.shutdownNow()
        Log.i(TAG, "automation accessibility service destroyed")
        super.onDestroy()
    }

    private fun handleCommand(op: String, args: JSONObject): JSONObject = when (op) {
        "observe" -> observe(args)
        "act" -> act(args)
        "app" -> app(args)
        "device" -> device(args)
        "status" -> status()
        "notifications" -> notifications(args)
        // Fault injection for the watchdog acceptance (tools/verify_v38_automation_watchdog.sh):
        // it deliberately occupies a command slot past the bridge deadline. Inert otherwise —
        // it touches no window and is only reachable over the host bridge.
        "selftest_sleep" -> {
            val ms = args.optInt("ms", 1_000).coerceIn(0, 60_000)
            Thread.sleep(ms.toLong())
            JSONObject().put("sleptMs", ms)
        }
        else -> throw AutomationException("unsupported_op", "unsupported automation op: $op")
    }

    // Reads what the opt-in NotificationListenerService buffered. Items exist only after the user
    // granted notification access; the host still decides whether an AI may ask for them.
    private fun notifications(args: JSONObject): JSONObject {
        val limit = args.optInt("limit", 10).coerceIn(1, 30)
        val sinceMs = args.optLong("sinceMs", 0L)
        val clear = args.optBoolean("clear", false)
        val cleared = if (clear) AdhNotificationListener.clear() else 0
        return AdhNotificationListener.snapshot(limit, sinceMs)
            .put("granted", AdhNotificationListener.isGranted(this))
            .put("listener", AdhNotificationListener.stats())
            .put("cleared", cleared)
    }

    private fun status(): JSONObject = JSONObject()
        .put("activePackage", activePackage())
        .put("activity", lastActivity)
        .put("sdk", Build.VERSION.SDK_INT)
        .put("screenshot", Build.VERSION.SDK_INT >= Build.VERSION_CODES.R)
        .put("snapshots", snapshots.size)
        .put("notifications", AdhNotificationListener.stats().put("granted", AdhNotificationListener.isGranted(this)))
        .put("bridge", bridge?.stats() ?: JSONObject())

    private fun observe(args: JSONObject): JSONObject {
        val mode = args.optString("mode", "auto").ifBlank { "auto" }
        val allowedPackages = stringSet(args.optJSONArray("allowedPackages"))
        val requestedPackage = args.optString("package").takeIf { it.isNotBlank() }
        val screenshotEnabled = args.optBoolean("screenshot", true)
        val maxNodes = args.optInt("maxNodes", 300).coerceIn(20, 2000)
        val maxDepth = args.optInt("maxDepth", 50).coerceIn(1, 100)
        val interactiveOnly = args.optBoolean("interactiveOnly", false)
        val screenshotMaxDimension = args.optInt("screenshotMaxDimension", 1280).coerceIn(480, 2400)
        val includeScreenshot = args.opt("includeScreenshot")

        val root = rootInActiveWindow
        val active = root?.packageName?.toString()?.takeIf { it.isNotBlank() } ?: activePackage()
        ensurePackageAllowed(active, allowedPackages, requestedPackage)

        val screen = screenJson()
        val tree = if (mode == "visual") null else buildTree(root, maxNodes, maxDepth, interactiveOnly)
        if (tree != null && tree.nodes.isNotEmpty()) {
            val snapshotId = storeSnapshot(active, screen, tree.nodes)
            return JSONObject()
                .put("snapshotId", snapshotId)
                .put("mode", "tree")
                .put("activePackage", active)
                .put("activity", lastActivity)
                .put("screen", screen)
                .put("nodes", tree.json)
                .put("truncated", tree.truncated)
                .put("screenshot", screenshotForMode(includeScreenshot, screenshotEnabled, false, screenshotMaxDimension))
        }

        if (mode == "tree") throw AutomationException("tree_unavailable", "active window has no usable accessibility nodes")
        if (!screenshotEnabled) throw AutomationException("screenshot_disabled", "screenshot fallback is disabled on the host")
        if (includeScreenshot == false) throw AutomationException("screenshot_disabled", "caller disabled screenshot fallback")
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.R) {
            throw AutomationException("screenshot_unsupported", "screenshot requires Android 11 or newer")
        }
        return JSONObject()
            .put("snapshotId", JSONObject.NULL)
            .put("mode", "visual")
            .put("reason", "empty_or_non_semantic_tree")
            .put("activePackage", active)
            .put("activity", lastActivity)
            .put("screen", screen)
            .put("nodes", JSONArray())
            .put("truncated", false)
            .put("screenshot", captureScreenshot(screenshotMaxDimension))
    }

    private fun act(args: JSONObject): JSONObject {
        val action = args.optString("action")
        val snapshotId = args.optString("snapshotId").takeIf { it.isNotBlank() }
        val ref = args.optString("ref").takeIf { it.isNotBlank() }
        val snapshot = snapshotId?.let { snapshots[it] }
        val active = rootInActiveWindow?.packageName?.toString()?.takeIf { it.isNotBlank() }
            ?: snapshot?.packageName
            ?: activePackage()
        val allowedPackages = stringSet(args.optJSONArray("allowedPackages"))
        val requestedPackage = args.optString("package").takeIf { it.isNotBlank() }
        ensurePackageAllowed(active, allowedPackages, requestedPackage)
        if (snapshot != null && active != snapshot.packageName) {
            throw AutomationException("stale_snapshot", "active package changed from ${snapshot.packageName} to $active")
        }

        // Sample the visible labels twice before acting: an app that is still animating after the
        // previous command would otherwise make the post-action comparison report a change that
        // the action never caused (and that suppresses the root-input fallback).
        val beforeA = windowSignature()
        Thread.sleep(260)
        val beforeB = windowSignature()
        val before = if (beforeA != null && beforeA == beforeB) beforeA else null

        val result = when (action) {
            "tap" -> tap(args, snapshot, ref)
            "long_press" -> longPress(args, snapshot, ref)
            "swipe" -> swipe(args)
            "input" -> input(args)
            "scroll" -> scroll(args, snapshot, ref)
            "set_text" -> setText(args, snapshot, ref)
            "global" -> global(args)
            "ime" -> ime(args)
            else -> throw AutomationException("unsupported_action", "unsupported action: $action")
        }
        if (action == "tap" || action == "swipe" || action == "input") {
            // A few Compose UIs accept dispatchGesture and never act on it: the callback completes
            // while the window stays identical. Report that instead of pretending the action worked.
            Thread.sleep(260)
            val afterA = windowSignature()
            Thread.sleep(160)
            val afterB = windowSignature()
            val after = if (afterA != null && afterA == afterB) afterA else null
            // Unknown before (screen still settling) reports changed:true on purpose: the fallback
            // exists for apps that silently swallow gestures, and a wrong true is harmless there
            // while a wrong false would double-tap a UI that DID react.
            result.put("changed", before == null || after == null || before != after)
        }
        if (snapshotId != null) snapshots.remove(snapshotId)
        return result.put("activePackage", active)
    }

    private fun tap(args: JSONObject, snapshot: Snapshot?, ref: String?): JSONObject {
        val node = ref?.let { snapshot?.nodes?.get(it) }
        if (ref != null && node == null) throw AutomationException("stale_ref", "unknown or expired node ref: $ref")
        if (node != null) {
            refreshOrThrow(node)
            val clickable = clickableAncestor(node)
            if (clickable?.performAction(AccessibilityNodeInfo.ACTION_CLICK) == true) {
                return JSONObject().put("action", "tap").put("target", "ref").put("ref", ref)
            }
            val bounds = rectOf(node)
            if (bounds.width() > 0 && bounds.height() > 0) {
                if (gestureTap(bounds.exactCenterX(), bounds.exactCenterY(), 60L)) {
                    return JSONObject().put("action", "tap").put("target", "node-center").put("ref", ref)
                }
            }
        }
        val point = point(args)
        if (!gestureTap(point.first, point.second, 60L)) throw AutomationException("gesture_rejected", "tap gesture was rejected")
        return JSONObject().put("action", "tap").put("target", "coordinate")
    }

    private fun longPress(args: JSONObject, snapshot: Snapshot?, ref: String?): JSONObject {
        val node = ref?.let { snapshot?.nodes?.get(it) }
        if (ref != null && node == null) throw AutomationException("stale_ref", "unknown or expired node ref: $ref")
        if (node != null) {
            refreshOrThrow(node)
            if (node.performAction(AccessibilityNodeInfo.ACTION_LONG_CLICK)) {
                return JSONObject().put("action", "long_press").put("target", "ref").put("ref", ref)
            }
            val bounds = rectOf(node)
            if (bounds.width() > 0 && bounds.height() > 0 && gestureTap(bounds.exactCenterX(), bounds.exactCenterY(), 800L)) {
                return JSONObject().put("action", "long_press").put("target", "node-center").put("ref", ref)
            }
        }
        val point = point(args)
        if (!gestureTap(point.first, point.second, 800L)) throw AutomationException("gesture_rejected", "long press gesture was rejected")
        return JSONObject().put("action", "long_press").put("target", "coordinate")
    }

    private fun swipe(args: JSONObject): JSONObject {
        val startX = coordinate(args.optDouble("x", Double.NaN), screenWidth(), args.optString("coordinateSpace", "normalized"))
        val startY = coordinate(args.optDouble("y", Double.NaN), screenHeight(), args.optString("coordinateSpace", "normalized"))
        val endX = coordinate(args.optDouble("x2", Double.NaN), screenWidth(), args.optString("coordinateSpace", "normalized"))
        val endY = coordinate(args.optDouble("y2", Double.NaN), screenHeight(), args.optString("coordinateSpace", "normalized"))
        if (startX.isNaN() || startY.isNaN() || endX.isNaN() || endY.isNaN()) {
            throw AutomationException("bad_coordinates", "swipe requires x, y, x2 and y2")
        }
        val duration = args.optLong("durationMs", 320L).coerceIn(80L, 3_000L)
        val path = Path().apply {
            moveTo(startX, startY)
            lineTo(endX, endY)
        }
        val gesture = GestureDescription.Builder()
            .addStroke(GestureDescription.StrokeDescription(path, 0L, duration))
            .build()
        if (!dispatchGestureAndWait(gesture)) throw AutomationException("gesture_rejected", "swipe gesture was rejected")
        return JSONObject().put("action", "swipe")
    }




    private fun device(args: JSONObject): JSONObject {
        val action = args.optString("action", "status")
        return when (action) {
            "status" -> powerStatus()
            "wake" -> {
                requireDeviceDaemon().wakeScreen()
                powerStatus()
            }
            "unlock" -> {
                val daemon = requireDeviceDaemon()
                daemon.wakeScreen()
                val dismissed = daemon.dismissKeyguard()
                powerStatus().put("dismissed", dismissed)
            }
            "lock" -> {
                if (Build.VERSION.SDK_INT < Build.VERSION_CODES.P) {
                    throw AutomationException("device_unsupported", "lock action requires Android 9 or newer")
                }
                if (!performGlobalAction(GLOBAL_ACTION_LOCK_SCREEN)) {
                    throw AutomationException("device_rejected", "system rejected lock action")
                }
                JSONObject().put("action", "lock").put("result", "ok")
            }
            else -> throw AutomationException("bad_device_action", "device action must be status, wake, unlock or lock")
        }
    }

    private fun powerStatus(): JSONObject {
        val power = getSystemService(PowerManager::class.java)
        val keyguard = getSystemService(KeyguardManager::class.java)
        return JSONObject()
            .put("interactive", power?.isInteractive ?: false)
            .put("locked", keyguard?.isKeyguardLocked ?: false)
    }

    private fun requireDeviceDaemon(): com.adh.manager.data.DaemonClient {
        val client = DaemonBinderProvider.awaitClient(3_000)
            ?: throw AutomationException("device_daemon_unavailable", "ADH Device Daemon is unavailable")
        if (client.protocolVersion < AdhProtocol.MIN_DEVICE_POWER_VERSION) {
            throw AutomationException("device_daemon_old", "Device Daemon protocol ${client.protocolVersion} has no power control")
        }
        return client
    }
    /**
     * Raw input injection through the root Device Daemon. Fallback for UIs that accept an
     * AccessibilityService gesture but never act on it (observed on SukiSU Ultra and the
     * Vector/LSPosed manager, both Compose): the gesture reports success, the screen never changes.
     * `input tap|swipe` goes through the system input pipeline instead and does reach them.
     * Coordinates are absolute display pixels, matching the space reported by observe.
     */
    private fun input(args: JSONObject): JSONObject {
        val mode = args.optString("mode", "tap").ifBlank { "tap" }.lowercase()
        val client = requireInputInjectionDaemon()
        return when (mode) {
            "tap" -> {
                val point = pixelPoint(args)
                if (!client.injectInputTap(point.first.toInt(), point.second.toInt())) {
                    throw AutomationException("input_injection_rejected", "root input tap returned failure")
                }
                JSONObject().put("action", "input").put("mode", "tap")
                    .put("x", point.first.toInt()).put("y", point.second.toInt())
            }
            "swipe" -> {
                val start = pixelPoint(args)
                val end = pixelPoint(args, "x2", "y2")
                val duration = args.optInt("durationMs", 320).coerceIn(1, 3_000)
                if (!client.injectInputSwipe(start.first.toInt(), start.second.toInt(), end.first.toInt(), end.second.toInt(), duration)) {
                    throw AutomationException("input_injection_rejected", "root input swipe returned failure")
                }
                JSONObject().put("action", "input").put("mode", "swipe").put("durationMs", duration)
            }
            else -> throw AutomationException("bad_input_mode", "input mode must be tap or swipe")
        }
    }

    private fun requireInputInjectionDaemon(): com.adh.manager.data.DaemonClient {
        val client = DaemonBinderProvider.awaitClient(3_000)
            ?: throw AutomationException("device_daemon_unavailable", "ADH Device Daemon is unavailable")
        if (client.protocolVersion < AdhProtocol.MIN_INPUT_INJECTION_VERSION) {
            throw AutomationException(
                "device_daemon_old",
                "Device Daemon protocol " + client.protocolVersion + " has no raw input injection (needs v9)",
            )
        }
        return client
    }

    private fun pixelPoint(args: JSONObject, xKey: String = "x", yKey: String = "y"): Pair<Float, Float> {
        val space = args.optString("coordinateSpace", "normalized")
        val x = coordinate(args.optDouble(xKey, Double.NaN), screenWidth(), space)
        val y = coordinate(args.optDouble(yKey, Double.NaN), screenHeight(), space)
        if (x.isNaN() || y.isNaN()) throw AutomationException("bad_coordinates", "input requires x and y")
        return x to y
    }
    /**
     * Fingerprint of what is actually visible on screen, used to tell whether an action moved the
     * UI. It hashes the sorted set of visible text / content descriptions:
     *   - a tab switch, dialog or page load changes which labels are visible  -> changed:true
     *   - a WebView scroll brings different result rows into view             -> changed:true
     *   - animations, ripples and geometry-only redraws keep the same labels  -> changed:false
     * Geometry is deliberately NOT hashed: hashing it made SukiSU's blinking cursor read as a
     * change, which suppressed the root-input fallback exactly where it is needed.
     */
    private fun windowSignature(): String? {
        val root = rootInActiveWindow ?: return null
        return try {
            val display = screenBounds()
            val tokens = sortedSetOf<String>()
            val bounds = Rect()
            var budget = 120
            fun visit(node: AccessibilityNodeInfo) {
                if (budget <= 0) return
                budget--
                node.getBoundsInScreen(bounds)
                val visible = !bounds.isEmpty && bounds.right > display.left && bounds.left < display.right &&
                    bounds.bottom > display.top && bounds.top < display.bottom
                if (visible) {
                    node.text?.takeIf { it.isNotEmpty() }?.let { tokens.add("t:" + it) }
                    node.contentDescription?.takeIf { it.isNotEmpty() }?.let { tokens.add("d:" + it) }
                }
                for (index in 0 until node.childCount) {
                    val child = node.getChild(index) ?: continue
                    visit(child)
                }
            }
            visit(root)
            MessageDigest.getInstance("SHA-1")
                .digest(tokens.joinToString("\u0000").toByteArray(Charsets.UTF_8))
                .joinToString("") { "%02x".format(it) }
        } catch (_: Throwable) {
            null
        } finally {
            @Suppress("DEPRECATION")
            root.recycle()
        }
    }

    private fun app(args: JSONObject): JSONObject {
        val action = args.optString("action")
        val packageName = args.optString("package").trim()
        val allowedPackages = stringSet(args.optJSONArray("allowedPackages"))
        if (packageName.isEmpty()) throw AutomationException("missing_package", "app action requires a package")
        if (allowedPackages.isEmpty() || packageName !in allowedPackages) {
            throw AutomationException("blocked_package", "package $packageName is not in the automation allowlist")
        }
        return when (action) {
            "open" -> openApp(packageName)
            "stop" -> controlApp(packageName, restart = false)
            "restart" -> controlApp(packageName, restart = true)
            else -> throw AutomationException("bad_app_action", "app action must be open, stop or restart")
        }
    }

    private fun openApp(packageName: String): JSONObject {
        if (!PackageControl.mayControl(packageName)) {
            throw AutomationException("app_control_denied", "package $packageName cannot be controlled")
        }
        val daemon = DaemonBinderProvider.awaitClient(1_500)
        if (daemon != null && daemon.protocolVersion >= AdhProtocol.MIN_APP_OPEN_VERSION) {
            val result = daemon.controlPackage(packageName, PackageControl.ACTION_OPEN)
            if (result == PackageControl.RESULT_OK) {
                return JSONObject()
                    .put("action", "open")
                    .put("package", packageName)
                    .put("result", result)
                    .put("via", "device-daemon")
            }
            if (result != PackageControl.RESULT_NO_LAUNCHER && result != PackageControl.RESULT_DENIED) {
                throw AutomationException("app_control_failed", "device daemon returned $result")
            }
        }
        val intent = packageManager.getLaunchIntentForPackage(packageName)
            ?: throw AutomationException("no_launcher", "package $packageName has no launcher activity")
        intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_RESET_TASK_IF_NEEDED)
        startActivity(intent)
        return JSONObject().put("action", "open").put("package", packageName).put("result", "ok").put("via", "accessibility-fallback")
    }

    private fun controlApp(packageName: String, restart: Boolean): JSONObject {
        if (!PackageControl.mayControl(packageName)) {
            throw AutomationException("app_control_denied", "package $packageName cannot be controlled")
        }
        val client = DaemonBinderProvider.awaitClient(3_000)
            ?: throw AutomationException("device_daemon_unavailable", "ADH Device Daemon is unavailable")
        val action = if (restart) PackageControl.ACTION_RESTART else PackageControl.ACTION_STOP
        val result = client.controlPackage(packageName, action)
        if (result != PackageControl.RESULT_OK) {
            throw AutomationException("app_control_failed", "device daemon returned $result")
        }
        return JSONObject().put("action", action).put("package", packageName).put("result", result)
    }

    private fun scroll(args: JSONObject, snapshot: Snapshot?, ref: String?): JSONObject {
        val refNode = ref?.let { snapshot?.nodes?.get(it) }
        if (ref != null && refNode == null) throw AutomationException("stale_ref", "unknown or expired node ref: $ref")
        val node = refNode?.let { scrollableAncestor(it) ?: it } ?: rootInActiveWindow
            ?: throw AutomationException("no_scroll_target", "no active scrollable window")
        if (refNode != null) refreshOrThrow(node)
        val direction = args.optString("direction", "forward")
        val action = when (direction) {
            "forward" -> AccessibilityNodeInfo.ACTION_SCROLL_FORWARD
            "backward" -> AccessibilityNodeInfo.ACTION_SCROLL_BACKWARD
            else -> throw AutomationException("bad_direction", "scroll direction must be forward or backward")
        }
        if (!node.performAction(action)) {
            throw AutomationException("scroll_rejected", "active window rejected scroll $direction")
        }
        return JSONObject()
            .put("action", "scroll")
            .put("direction", direction)
            .put("target", if (ref != null) "ref" else "active-window")
    }
    private fun setText(args: JSONObject, snapshot: Snapshot?, ref: String?): JSONObject {
        if (ref.isNullOrBlank()) throw AutomationException("missing_ref", "set_text requires a node ref")
        val node = snapshot?.nodes?.get(ref) ?: throw AutomationException("stale_ref", "unknown node ref: $ref")
        refreshOrThrow(node)
        val editable = editableAncestor(node) ?: throw AutomationException("not_editable", "node is not editable")
        val value = args.optString("text")
        val bundle = Bundle().apply {
            putString(AccessibilityNodeInfo.ACTION_ARGUMENT_SET_TEXT_CHARSEQUENCE, value)
        }
        // Focus + click first: ACTION_IME_ENTER only reaches the app when an IME is attached, and
        // a fresh screen has none. (Observed on-device: without the click the action returned true
        // but no editor-action ever fired, so "submitted" would have been a lie.)
        editable.performAction(AccessibilityNodeInfo.ACTION_FOCUS)
        editable.performAction(AccessibilityNodeInfo.ACTION_CLICK)
        if (args.optBoolean("submit", false)) Thread.sleep(250)
        if (!editable.performAction(AccessibilityNodeInfo.ACTION_SET_TEXT, bundle)) {
            throw AutomationException("set_text_rejected", "node rejected ACTION_SET_TEXT")
        }
        val result = JSONObject().put("action", "set_text").put("target", "ref").put("ref", ref)
        if (args.optBoolean("submit", false)) {
            // The keyboard's action button (search / send / done). ACTION_IME_ENTER needs API 30;
            // without it we fail loudly rather than pretending the form was submitted.
            if (Build.VERSION.SDK_INT < Build.VERSION_CODES.R) {
                throw AutomationException("ime_enter_unsupported", "submit requires Android 11 or newer")
            }
            // Only the AccessibilityAction form exists (there is no plain int constant).
            val imeEnterAction = AccessibilityNodeInfo.AccessibilityAction.ACTION_IME_ENTER.id
            if (!editable.performAction(imeEnterAction)) {
                throw AutomationException("ime_enter_rejected", "the field rejected ACTION_IME_ENTER")
            }
            result.put("submitted", true)
        }
        return result
    }

    /**
     * Press the keyboard action key (search / send / done / go) on whatever field currently has
     * focus. Some apps (HeyTap browser) ignore a tap on their own search button - the accessibility
     * click lands, nothing submits - while the IME action reliably triggers the same handler the
     * on-screen keyboard uses. Fail loudly when the platform is too old or no field is focused.
     */
    private fun ime(args: JSONObject): JSONObject {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.R) {
            throw AutomationException("ime_action_unsupported", "IME action requires Android 11 or newer")
        }
        val requested = args.optString("key", "search").ifBlank { "search" }
        val actionId = when (requested) {
            "search" -> AccessibilityNodeInfo.AccessibilityAction.ACTION_IME_ENTER.id
            "done", "go", "send", "next", "previous" -> AccessibilityNodeInfo.AccessibilityAction.ACTION_IME_ENTER.id
            else -> throw AutomationException("bad_ime_key", "ime key must be search, done, go, send, next or previous")
        }
        val node = focusedEditable()
            ?: findFirstEditable()
            ?: throw AutomationException("no_focused_field", "no editable field has focus; tap it first")
        val performed = node.performAction(actionId)
        if (!performed) throw AutomationException("ime_rejected", "field rejected the IME action ($requested)")
        return JSONObject().put("action", "ime").put("key", requested)
    }

    @Suppress("DEPRECATION")
    private fun focusedEditable(): AccessibilityNodeInfo? {
        val root = rootInActiveWindow ?: return null
        return try {
            root.findFocus(AccessibilityNodeInfo.FOCUS_INPUT)?.takeIf { it.isEditable }
        } finally {
            root.recycle()
        }
    }

    @Suppress("DEPRECATION")
    private fun findFirstEditable(): AccessibilityNodeInfo? {
        val root = rootInActiveWindow ?: return null
        return try {
            val queue = ArrayDeque<AccessibilityNodeInfo>()
            queue.add(root)
            var budget = 200
            while (queue.isNotEmpty() && budget-- > 0) {
                val node = queue.removeFirst()
                if (node.isEditable && node.isVisibleToUser) return node
                for (index in 0 until node.childCount) node.getChild(index)?.let { queue.add(it) }
            }
            null
        } finally {
            root.recycle()
        }
    }

    private fun global(args: JSONObject): JSONObject {
        val key = args.optString("key")
        val action = when (key) {
            "back" -> GLOBAL_ACTION_BACK
            "home" -> GLOBAL_ACTION_HOME
            "recents" -> GLOBAL_ACTION_RECENTS
            "notifications" -> GLOBAL_ACTION_NOTIFICATIONS
            "quick_settings" -> GLOBAL_ACTION_QUICK_SETTINGS
            "power" -> GLOBAL_ACTION_POWER_DIALOG
            "lock" -> if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                GLOBAL_ACTION_LOCK_SCREEN
            } else {
                throw AutomationException("global_unsupported", "lock screen requires Android 9 or newer")
            }
            "screenshot" -> if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                GLOBAL_ACTION_TAKE_SCREENSHOT
            } else {
                throw AutomationException("global_unsupported", "screenshot requires Android 11 or newer")
            }
            else -> throw AutomationException("bad_key", "global key must be back, home, recents, notifications, quick_settings, power, lock or screenshot")
        }
        if (!performGlobalAction(action)) throw AutomationException("global_rejected", "system rejected global action: $key")
        return JSONObject().put("action", "global").put("key", key)
    }

    private fun buildTree(
        root: AccessibilityNodeInfo?,
        maxNodes: Int,
        maxDepth: Int,
        interactiveOnly: Boolean,
    ): TreeResult? {
        if (root == null) return null
        val json = JSONArray()
        val nodes = LinkedHashMap<String, AccessibilityNodeInfo>()
        val queue = ArrayDeque<Pair<AccessibilityNodeInfo, Int>>()
        queue.add(root to 0)
        var refSeq = 0
        var truncated = false
        val deadline = SystemClock.uptimeMillis() + OBSERVE_BUDGET_MS
        while (queue.isNotEmpty() && nodes.size < maxNodes) {
            if (SystemClock.uptimeMillis() > deadline) {
                truncated = true
                break
            }
            try {
                val (node, depth) = queue.removeFirst()
                if (node.isVisibleToUser) {
                    val useful = isUseful(node, interactiveOnly)
                    val bounds = rectOf(node)
                    if (useful && bounds.width() > 0 && bounds.height() > 0) {
                        val ref = "n${refSeq++}"
                        nodes[ref] = node
                        json.put(nodeJson(ref, node, bounds, depth))
                    }
                }
                if (depth >= maxDepth) {
                    if (node.childCount > 0) truncated = true
                    continue
                }
                for (index in 0 until node.childCount) {
                    if (queue.size >= QUEUE_LIMIT) {
                        truncated = true
                        break
                    }
                    node.getChild(index)?.let { queue.add(it to depth + 1) }
                }
            } catch (error: Throwable) {
                truncated = true
                Log.w(TAG, "tree traversal skipped stale node", error)
            }
        }
        return TreeResult(json, nodes, truncated || nodes.size >= maxNodes)
    }

    private fun nodeJson(ref: String, node: AccessibilityNodeInfo, bounds: Rect, depth: Int): JSONObject {
        val result = JSONObject()
            .put("ref", ref)
            .put("depth", depth)
            .put("className", node.className?.toString() ?: "")
            .put("package", node.packageName?.toString() ?: "")
            .put("bounds", JSONArray(listOf(bounds.left, bounds.top, bounds.right, bounds.bottom)))
            .put("clickable", node.isClickable)
            .put("editable", node.isEditable)
            .put("scrollable", node.isScrollable)
            .put("enabled", node.isEnabled)
            .put("selected", node.isSelected)
            .put("checked", node.isChecked)
        node.text?.toString()?.trim()?.takeIf { it.isNotEmpty() }?.let { result.put("text", it) }
        node.contentDescription?.toString()?.trim()?.takeIf { it.isNotEmpty() }?.let { result.put("contentDescription", it) }
        node.hintText?.toString()?.trim()?.takeIf { it.isNotEmpty() }?.let { result.put("hint", it) }
        node.viewIdResourceName?.takeIf { it.isNotBlank() }?.let { result.put("resourceId", it) }
        val actions = JSONArray()
        if (node.isClickable || hasAction(node, AccessibilityNodeInfo.ACTION_CLICK)) actions.put("click")
        if (node.isEditable || hasAction(node, AccessibilityNodeInfo.ACTION_SET_TEXT)) actions.put("set_text")
        if (node.isScrollable || hasAction(node, AccessibilityNodeInfo.ACTION_SCROLL_FORWARD)) actions.put("scroll_forward")
        if (node.isScrollable || hasAction(node, AccessibilityNodeInfo.ACTION_SCROLL_BACKWARD)) actions.put("scroll_backward")
        result.put("actions", actions)
        return result
    }

    private fun isUseful(node: AccessibilityNodeInfo, interactiveOnly: Boolean): Boolean {
        val interactive = node.isClickable || node.isEditable || node.isScrollable || node.isCheckable ||
            hasAction(node, AccessibilityNodeInfo.ACTION_CLICK) ||
            hasAction(node, AccessibilityNodeInfo.ACTION_LONG_CLICK) ||
            hasAction(node, AccessibilityNodeInfo.ACTION_SET_TEXT) ||
            hasAction(node, AccessibilityNodeInfo.ACTION_SCROLL_FORWARD) ||
            hasAction(node, AccessibilityNodeInfo.ACTION_SCROLL_BACKWARD)
        if (interactiveOnly) return interactive
        if (!node.text.isNullOrBlank()) return true
        if (!node.contentDescription.isNullOrBlank()) return true
        if (!node.hintText.isNullOrBlank()) return true
        return interactive
    }

    private fun hasAction(node: AccessibilityNodeInfo, actionId: Int): Boolean =
        node.actionList.any { it.id == actionId }

    private fun clickableAncestor(node: AccessibilityNodeInfo): AccessibilityNodeInfo? =
        ancestor(node, 8) { it.isClickable || hasAction(it, AccessibilityNodeInfo.ACTION_CLICK) }

    private fun scrollableAncestor(node: AccessibilityNodeInfo): AccessibilityNodeInfo? =
        ancestor(node, 8) {
            it.isScrollable ||
                hasAction(it, AccessibilityNodeInfo.ACTION_SCROLL_FORWARD) ||
                hasAction(it, AccessibilityNodeInfo.ACTION_SCROLL_BACKWARD)
        }
    private fun editableAncestor(node: AccessibilityNodeInfo): AccessibilityNodeInfo? =
        ancestor(node, 8) { it.isEditable || hasAction(it, AccessibilityNodeInfo.ACTION_SET_TEXT) }

    private inline fun ancestor(node: AccessibilityNodeInfo, limit: Int, predicate: (AccessibilityNodeInfo) -> Boolean): AccessibilityNodeInfo? {
        var current: AccessibilityNodeInfo? = node
        var depth = 0
        while (current != null && depth <= limit) {
            if (predicate(current)) return current
            current = current.parent
            depth++
        }
        return null
    }

    private fun refreshOrThrow(node: AccessibilityNodeInfo) {
        if (!node.refresh()) throw AutomationException("stale_ref", "node ref is no longer valid")
    }

    private fun storeSnapshot(packageName: String, screen: JSONObject, nodes: Map<String, AccessibilityNodeInfo>): String {
        val id = "s-${System.currentTimeMillis().toString(36)}-${snapshotSeq++}"
        snapshots[id] = Snapshot(id, packageName, screen, nodes)
        snapshotOrder.addLast(id)
        while (snapshotOrder.size > MAX_SNAPSHOTS) snapshots.remove(snapshotOrder.removeFirst())
        return id
    }

    private fun ensurePackageAllowed(active: String, allowed: Set<String>, requested: String?) {
        if (allowed.isEmpty()) throw AutomationException("blocked_package", "automation package allowlist is empty")
        if (requested != null && requested != active) {
            throw AutomationException("blocked_package", "requested package $requested does not match active package $active")
        }
        if (active !in allowed) throw AutomationException("blocked_package", "active package $active is not in the automation allowlist")
    }

    private fun stringSet(array: JSONArray?): Set<String> {
        if (array == null) return emptySet()
        val values = linkedSetOf<String>()
        for (index in 0 until array.length()) array.optString(index).trim().takeIf { it.isNotEmpty() }?.let { values.add(it) }
        return values
    }

    private fun activePackage(): String {
        rootInActiveWindow?.packageName?.toString()?.takeIf { it.isNotBlank() }?.let { return it }
        return lastActivePackage
    }

    private fun rectOf(node: AccessibilityNodeInfo): Rect = Rect().also { node.getBoundsInScreen(it) }

    private fun point(args: JSONObject): Pair<Float, Float> {
        val x = coordinate(args.optDouble("x", Double.NaN), screenWidth(), args.optString("coordinateSpace", "normalized"))
        val y = coordinate(args.optDouble("y", Double.NaN), screenHeight(), args.optString("coordinateSpace", "normalized"))
        if (x.isNaN() || y.isNaN()) throw AutomationException("bad_coordinates", "coordinate action requires x and y")
        return x to y
    }

    private fun coordinate(value: Double, size: Int, space: String): Float {
        if (!value.isFinite()) return Float.NaN
        return if (space == "pixel") value.toFloat() else (value.coerceIn(0.0, 1.0) * size).toFloat()
    }

    private fun gestureTap(x: Float, y: Float, duration: Long): Boolean {
        val path = Path().apply { moveTo(x, y) }
        val gesture = GestureDescription.Builder()
            .addStroke(GestureDescription.StrokeDescription(path, 0L, duration))
            .build()
        return dispatchGestureAndWait(gesture)
    }

    private fun dispatchGestureAndWait(gesture: GestureDescription): Boolean {
        val latch = CountDownLatch(1)
        var completed = false
        var cancelled = false
        val callback = object : AccessibilityService.GestureResultCallback() {
            override fun onCompleted(gestureDescription: GestureDescription?) {
                completed = true
                latch.countDown()
            }

            override fun onCancelled(gestureDescription: GestureDescription?) {
                cancelled = true
                latch.countDown()
            }
        }
        if (!dispatchGesture(gesture, callback, null)) return false
        if (!latch.await(4, TimeUnit.SECONDS)) return false
        return completed && !cancelled
    }

    private fun screenshotForMode(value: Any?, enabled: Boolean, visualFallback: Boolean, maxDimension: Int): Any {
        val shouldCapture = when (value) {
            is Boolean -> value
            else -> visualFallback
        }
        return if (shouldCapture && enabled && Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) captureScreenshot(maxDimension) else JSONObject.NULL
    }

    private fun captureScreenshot(maxDimension: Int): JSONObject {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.R) {
            throw AutomationException("screenshot_unsupported", "screenshot requires Android 11 or newer")
        }
        val latch = CountDownLatch(1)
        var bitmap: Bitmap? = null
        var failure: String? = null
        var failureCode = 0
        val callback = object : AccessibilityService.TakeScreenshotCallback {
            override fun onSuccess(result: AccessibilityService.ScreenshotResult) {
                try {
                    val hardware = result.hardwareBuffer
                    val wrapped = Bitmap.wrapHardwareBuffer(hardware, result.colorSpace)
                    val copy = wrapped?.copy(Bitmap.Config.ARGB_8888, false)
                    hardware.close()
                    wrapped?.recycle()
                    bitmap = copy
                } catch (error: Exception) {
                    failure = error.message ?: "bitmap conversion failed"
                } finally {
                    latch.countDown()
                }
            }

            override fun onFailure(errorCode: Int) {
                failure = when (errorCode) {
                    1 -> "screenshot_internal_error (framework reported an internal error)"
                    2 -> "screenshot_no_accessibility_access (the service lost its access)"
                    3 -> "screenshot_rate_limited (another capture happened too recently)"
                    4 -> "screenshot_invalid_display"
                    5 -> "screenshot_invalid_window"
                    6 -> "screenshot_secure_window (FLAG_SECURE window)"
                    else -> "screenshot_failed (framework error code=$errorCode)"
                }
                failureCode = errorCode
                latch.countDown()
            }
        }
        takeScreenshot(Display.DEFAULT_DISPLAY, executor, callback)
        if (!latch.await(5, TimeUnit.SECONDS)) throw AutomationException("screenshot_timeout", "screenshot callback timed out")
        if (failureCode == 3) {
            // The framework rate-limits captures; one short wait is usually enough and saves the AI
            // a whole failed round trip.
            Thread.sleep(400)
            return captureScreenshot(maxDimension)
        }
        failure?.let { throw AutomationException("screenshot_failed", it) }
        val source = bitmap ?: throw AutomationException("screenshot_failed", "device returned no bitmap")
        // A FLAG_SECURE window (or a screen that is off) captures as a uniform black frame. Handing
        // that to the AI would be inventing a screen: spec §31.3 rule 4 says fail loudly instead.
        if (looksBlank(source)) {
            throw AutomationException(
                "screenshot_failed",
                "captured frame is blank/black — the window is probably protected (FLAG_SECURE) or the screen is off",
            )
        }
        val scale = min(1.0, maxDimension.toDouble() / max(source.width, source.height).coerceAtLeast(1))
        val output = if (scale < 1.0) {
            Bitmap.createScaledBitmap(source, (source.width * scale).toInt().coerceAtLeast(1), (source.height * scale).toInt().coerceAtLeast(1), true)
        } else source
        return try {
            val bytes = ByteArrayOutputStream().use { stream ->
                output.compress(Bitmap.CompressFormat.JPEG, 80, stream)
                stream.toByteArray()
            }
            JSONObject()
                .put("mimeType", "image/jpeg")
                .put("width", output.width)
                .put("height", output.height)
                .put("base64", Base64.encodeToString(bytes, Base64.NO_WRAP))
        } finally {
            if (output !== source) output.recycle()
            source.recycle()
        }
    }

    // Cheap "nothing was really drawn" check: sample a grid and treat an almost entirely black or
    // perfectly uniform dark frame as blank.
    private fun looksBlank(bitmap: Bitmap): Boolean {
        val stepX = max(1, bitmap.width / 48)
        val stepY = max(1, bitmap.height / 48)
        var sampled = 0
        var dark = 0
        var first: Int? = null
        var uniform = true
        var y = 0
        while (y < bitmap.height) {
            var x = 0
            while (x < bitmap.width) {
                val pixel = bitmap.getPixel(x, y)
                if (first == null) first = pixel else if (pixel != first) uniform = false
                val red = (pixel shr 16) and 0xff
                val green = (pixel shr 8) and 0xff
                val blue = pixel and 0xff
                if (red < 8 && green < 8 && blue < 8) dark++
                sampled++
                x += stepX
            }
            y += stepY
        }
        if (sampled == 0) return false
        return dark.toDouble() / sampled >= 0.98 || (uniform && dark == sampled)
    }

    private fun screenJson(): JSONObject = JSONObject()
        .put("width", screenWidth())
        .put("height", screenHeight())
        .put("rotation", resources.configuration.orientation)

    private fun screenWidth(): Int = screenBounds().width()

    private fun screenHeight(): Int = screenBounds().height()

    private fun screenBounds(): Rect {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            val manager = getSystemService(WindowManager::class.java)
            if (manager != null) return Rect(manager.maximumWindowMetrics.bounds)
        }
        val metrics = resources.displayMetrics
        return Rect(0, 0, metrics.widthPixels, metrics.heightPixels)
    }

    private data class TreeResult(
        val json: JSONArray,
        val nodes: Map<String, AccessibilityNodeInfo>,
        val truncated: Boolean,
    )

    private data class Snapshot(
        val id: String,
        val packageName: String,
        val screen: JSONObject,
        val nodes: Map<String, AccessibilityNodeInfo>,
    )

    companion object {
        private const val TAG = "AdhAutomationService"
        private const val MAX_SNAPSHOTS = 16
        private const val OBSERVE_BUDGET_MS = 4_000L
        private const val QUEUE_LIMIT = 20_000
        private const val BRIDGE_PREFS = "adh_automation"
        private const val BRIDGE_LAN_HOSTS = "lan_hosts"
    }

}
