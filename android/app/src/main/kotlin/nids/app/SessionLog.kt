package nids.app

import android.content.Context
import android.os.SystemClock
import org.json.JSONObject
import java.io.File
import java.security.MessageDigest
import java.util.UUID

/** Local bounded logs. No packet payloads are persisted by this writer. */
class SessionLog(private val ctx: Context, val model: String) {
    val id = UUID.randomUUID().toString()
    val started = SystemClock.elapsedRealtime()
    val modelHash = hash(ctx.assets.open(model).use { it.readBytes() })
    val configHash = hash(ctx.assets.open("runtime_config.txt").use { it.readBytes() })
    private val manifest = JSONObject(ctx.assets.open("model_manifest.json").bufferedReader().use { it.readText() })
    init {
        val files = manifest.getJSONObject("files")
        for (name in listOf(model, "runtime_config.txt", "golden/frames.txt", "golden/windows.txt", "golden/events.txt")) {
            require(hash(ctx.assets.open(name).use { it.readBytes() }) == files.getString(name)) { "asset integrity check failed: $name" }
        }
    }
    fun context(j: JSONObject): JSONObject = j.put("session_id", id).put("model_asset", model)
        .put("model_sha256", modelHash).put("config_sha256", configHash)
        .put("source_revision", manifest.getString("source_revision"))
        .put("app_version", "0.2.1").put("runtime_mode", "continuous-experimental")
        .put("recorded_at", System.currentTimeMillis() / 1000.0)
    @Synchronized fun write(name: String, j: JSONObject) {
        val f = File(ctx.filesDir, name)
        if (f.length() >= 5L * 1024 * 1024) {
            val old = File(ctx.filesDir, "$name.1")
            if (old.exists()) require(old.delete()) { "cannot rotate $name" }
            require(f.renameTo(old)) { "cannot rotate $name" }
        }
        f.appendText(context(j).toString() + "\n")
    }
    fun health(event: String, detail: String = "") = write("sessions.jsonl", JSONObject()
        .put("event", event).put("detail", detail)
        .put("uptime_s", (SystemClock.elapsedRealtime() - started) / 1000.0)
        .put("battery_percent", ctx.getSystemService(android.os.BatteryManager::class.java).getIntProperty(android.os.BatteryManager.BATTERY_PROPERTY_CAPACITY))
        .put("process_cpu_ms", android.os.Process.getElapsedCpuTime())
        .put("process_pss_kib", android.os.Debug.getPss())
        .put("thermal_status", if(android.os.Build.VERSION.SDK_INT>=29) ctx.getSystemService(android.os.PowerManager::class.java).currentThermalStatus else -1)
        .put("resource_note", "battery is device-wide; CPU/PSS include self-test and UI")
        .put("capture_uptime_s", Live.captureSeconds)
        .put("packets", Live.packets).put("frames", Live.frames).put("malformed", Live.malformed)
        .put("unsupported_link", Live.unsupported).put("skipped_fragments", Live.fragments)
        .put("inferences", Live.inferences).put("flow_alerts", Live.alerts).put("device_alarms", Live.deviceAlarms)
        .put("active_flows", Live.activeFlows).put("attributed_alerts", Live.attributed)
        .put("attribution_status", Live.attributionStatus)
        .put("capture_drop_count", JSONObject.NULL).put("capture_drop_note", "not available from pcap stream"))
    companion object {
        fun hash(bytes: ByteArray) = MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it.toInt() and 255) }
    }
}
