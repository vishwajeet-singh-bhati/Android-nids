package nids.app

import android.app.Instrumentation
import android.content.Context
import android.content.Intent
import android.os.SystemClock
import org.json.JSONObject
import java.io.File
import java.time.Instant

/** Sequential lexical inference only. Never visits a URL or emits user alerts. */
object UrlBenchmarkValidation {
    fun run(test: Instrumentation, context: Context, forceModel: Boolean = false): JSONObject {
        val input = File(context.filesDir, "url_benchmark_input.jsonl")
        val directory = File(context.filesDir, "rakshak_validation").apply { mkdirs() }
        val results = File(directory, "url_benchmark_results.jsonl")
        val progress = File(directory, "url_benchmark_progress.json")
        val monitorEnabled = context.getSharedPreferences("background_monitor", Context.MODE_PRIVATE)
            .getBoolean("enabled", false)
        val now = Instant.now()
        var count = 0
        var errors = 0
        val started = SystemClock.elapsedRealtime()
        try {
            results.bufferedWriter().use { writer ->
                val detector = LinkDetector.get(context)
                input.useLines { lines -> lines.filter { it.isNotBlank() }.forEach { line ->
                    val item = JSONObject(line)
                    val tick = SystemClock.elapsedRealtimeNanos()
                    val result = try { detector.check(item.getString("url"), now = now, includeDebug = forceModel) }
                    catch (error: Exception) { JSONObject().put("decision", JSONObject.NULL)
                        .put("error", error.javaClass.simpleName) }
                    if (!result.isNull("error") || result.optString("model_status") == "failed") errors++
                    val row = JSONObject().put("id", item.getInt("id")).put("result", result)
                        .put("elapsed_ms", (SystemClock.elapsedRealtimeNanos() - tick) / 1e6)
                    writer.write(row.toString()); writer.newLine()
                    count++
                    if (count % 25 == 0) {
                        writer.flush()
                        progress.writeText(JSONObject().put("completed", count).put("errors", errors)
                            .put("elapsed_ms", SystemClock.elapsedRealtime() - started).toString())
                    }
                } }
            }
            return JSONObject().put("passed", true).put("rows", count).put("errors", errors)
                .put("evaluation_time_utc", now.toString()).put("elapsed_ms", SystemClock.elapsedRealtime() - started)
                .put("model_version", LinkDetector.get(context).config.getString("model_version"))
                .put("force_model_scoring", forceModel)
                .put("network_monitor_enabled_before", monitorEnabled)
                .put("scope", "Sequential on-device URL inference; no website requests, notifications or ground-truth assumptions.")
        } finally {
            input.delete()
            if (monitorEnabled) test.runOnMainSync {
                context.startForegroundService(Intent(context, TsanetCaptureService::class.java))
            }
        }
    }
}
