package com.adh.sandbox

import android.content.Context
import android.net.wifi.WifiInfo
import android.os.Build
import android.provider.Settings
import android.telephony.TelephonyManager
import android.util.Log
import java.net.NetworkInterface

// Device-fingerprint collection triggers — fixtures for the detect_java fingerprint
// family (Settings.Secure android_id / TelephonyManager identifiers / MAC / package &
// sensor inventory). Hooks observe the call itself, so permission-denied calls still
// show up as hits (with the SecurityException in the error field) — that is fine for
// verification: what matters is the app *asked*.
object Fingerprint {
    private const val TAG = "ADH_SANDBOX"

    @JvmStatic
    fun run(ctx: Context): String {
        val out = ArrayList<String>(8)

        val androidId = try {
            Settings.Secure.getString(ctx.contentResolver, Settings.Secure.ANDROID_ID) ?: "null"
        } catch (t: Throwable) { "err" }
        out.add("aid=${androidId.take(8)}")

        val tm = ctx.getSystemService(Context.TELEPHONY_SERVICE) as? TelephonyManager
        if (tm != null) {
            val imei = try { @Suppress("DEPRECATION") tm.deviceId?.length ?: -1 } catch (t: Throwable) { -2 }
            val imsi = try { tm.subscriberId?.length ?: -1 } catch (t: Throwable) { -2 }
            out.add("imei.len=$imei imsi.len=$imsi")
        }

        val mac = try {
            @Suppress("DEPRECATION")
            (ctx.applicationContext.getSystemService(Context.WIFI_SERVICE) as? android.net.wifi.WifiManager)
                ?.connectionInfo?.macAddress ?: "null"
        } catch (t: Throwable) { "err" }
        out.add("mac=${mac.take(8)}")

        val niMac = try {
            NetworkInterface.getByName("wlan0")?.hardwareAddress?.size ?: -1
        } catch (t: Throwable) { -2 }
        out.add("ni.len=$niMac")

        val serial = try {
            if (Build.VERSION.SDK_INT >= 26) Build.getSerial().take(4) else @Suppress("DEPRECATION") Build.SERIAL.take(4)
        } catch (t: Throwable) { "err" }
        out.add("serial=$serial")

        val pkgs = try { ctx.packageManager.getInstalledPackages(0).size } catch (t: Throwable) { -1 }
        out.add("pkgs=$pkgs")

        val sensors = try {
            (ctx.getSystemService(Context.SENSOR_SERVICE) as? android.hardware.SensorManager)
                ?.getSensorList(android.hardware.Sensor.TYPE_ALL)?.size ?: -1
        } catch (t: Throwable) { -2 }
        out.add("sensors=$sensors")

        val summary = out.joinToString(" ")
        Log.i(TAG, "Fingerprint: $summary")
        return summary
    }
}
