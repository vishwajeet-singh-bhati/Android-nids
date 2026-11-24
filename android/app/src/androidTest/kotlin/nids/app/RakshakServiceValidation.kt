package nids.app

import android.app.Instrumentation
import android.app.NotificationManager
import android.content.Context
import android.content.Intent
import android.database.sqlite.SQLiteDatabase
import android.os.SystemClock
import org.json.JSONArray
import org.json.JSONObject
import java.io.File

/** Real service, store, notification and explanation queue; all created rows are marked TEST. */
object RakshakServiceValidation {
    fun run(test: Instrumentation, context: Context): JSONObject {
        val settings = SafetyControls.preferences(context)
        val before = HashMap(settings.all)
        val wasMonitoring = context.getSharedPreferences("background_monitor", Context.MODE_PRIVATE).getBoolean("enabled", false)
        val ids = ArrayList<String>()
        val fingerprints = ArrayList<String>()
        val results = JSONArray()
        val llamaAvailable = File(context.filesDir, "llama/Llama-3.2-1B-Instruct-SpinQuant_INT4_EO8.pte").exists()
        val source = "integration_fixture_" + java.util.UUID.randomUUID()
        val manager = context.getSystemService(NotificationManager::class.java)
        try {
            test.runOnMainSync {
                if (wasMonitoring) context.startService(Intent(context, TsanetCaptureService::class.java).setAction(TsanetCaptureService.STOP))
                SafetyControls.set(context, SafetyControls.SMS, true)
                SafetyControls.set(context, SafetyControls.URL, true)
                SafetyControls.set(context, SafetyControls.INCOMING, false)
            }
            val stopped = SystemClock.elapsedRealtime() + 20000
            while (LearnedLive.running && SystemClock.elapsedRealtime() < stopped) Thread.sleep(100)
            check(!LearnedLive.running) { "Capture did not pause for independent safety test" }
            val url = test.context.assets.open("rakshak/url_reference.jsonl").bufferedReader().use {
                // A model-only positive remains stable after the bundled feed expires.
                it.lineSequence().filter { line -> line.isNotBlank() }.map { line -> JSONObject(line) }
                    .first { row -> row.optString("source") == "model" && row.optString("decision") == "PHISHING" }.getString("input")
            }
            // URL checks must work with the SMS classifier disabled, including
            // a warning before any deeper SMS stage and no model role without links.
            SafetyControls.set(context, SafetyControls.SMS, false)
            var earlyLinkWarning = false
            val linkMessage = SafetyPipeline.analyze(context, "Please read " + url, "message") { early ->
                earlyLinkWarning = early.optString("risk_level") == "high" && early.optInt("links_checked") == 1
            }
            check(earlyLinkWarning && linkMessage.getString("risk_level") == "high")
            check(linkMessage.getString("sms_status") == "disabled")
            val noLink = SafetyPipeline.analyze(context, "Hello, see you tomorrow.", "message")
            check(noLink.getInt("links_checked") == 0 && noLink.getString("risk_level") == "low")
            SafetyControls.set(context, SafetyControls.SMS, true)
            val barePositive = SafetyPipeline.analyze(context, url, "message")
            check(barePositive.getString("sms_routing_reason") == "fast_path_link_only")
            check(barePositive.getString("risk_level") == "high") { "URL fast path hid a phishing verdict" }
            for ((domain, input) in listOf("message" to "Please share your OTP code 846210 to verify your account immediately.", "url" to url, "message" to url)) {
                var request = ""
                test.runOnMainSync { request = SafetyAnalysisService.submit(context, input, domain, source) }
                fingerprints.add("safety|" + request)
                var row: JSONObject? = null
                val deadline = SystemClock.elapsedRealtime() + 180000
                while (SystemClock.elapsedRealtime() < deadline) {
                    row = ObservationStore.list(context, 200).firstOrNull { it.optString("fingerprint") == "safety|" + request }
                    if (row != null && row.optString("explanation_status") in setOf("complete", "failed")) break
                    Thread.sleep(200)
                }
                val saved = row ?: error("No safety observation for " + domain)
                ids.add(saved.getString("id"))
                val state = saved.getString("explanation_status")
                check(state == if (llamaAvailable) "complete" else "failed") { "Unexpected explanation state " + state }
                val facts = saved.getJSONObject("model_evidence")
                check(facts.getBoolean("test_only") && facts.getString("phase") == "final")
                check("846210" !in saved.toString() && input !in saved.toString()) { "Raw content reached history" }
                // Completion is persisted before the main-thread notification
                // update and NotificationManager's asynchronous visibility.
                val notificationId = saved.getString("id").hashCode()
                val notificationDeadline = SystemClock.elapsedRealtime() + 5000
                while (manager.activeNotifications.none { it.id == notificationId } &&
                    SystemClock.elapsedRealtime() < notificationDeadline) Thread.sleep(100)
                check(manager.activeNotifications.any { it.id == notificationId }) { "Notification missing for " + domain }
                check(!LearnedLive.running) { "Safety queue restarted capture" }
                val text = HybridActivityNote.display(saved)
                check("What happened" in text && "What you can do" in text)
                results.put(JSONObject().put("domain", domain).put("risk_level", facts.getString("risk_level"))
                    .put("explanation_status", state).put("llama_guidance_accepted", saved.optJSONObject("explanation")?.optBoolean("generated_text_accepted") ?: false)
                    .put("notification_verified", true).put("raw_content_absent", true))
            }
            return JSONObject().put("passed", true).put("capture_paused_throughout", true)
                .put("llama_model_available", llamaAvailable).put("events", results)
                .put("scope", "Marked transient fixtures through the real foreground service. No carrier SMS sent. Missing Llama validates fallback only.")
        } finally {
            test.runOnMainSync {
                ids.forEach { manager.cancel(it.hashCode()) }
                if (LlamaLive.observationId in ids) LlamaClient.cancel("Integration fixture cleanup")
                LlamaClient.releaseIfIdle()
            }
            SQLiteDatabase.openDatabase(File(context.filesDir, "activity_history_v1.db").absolutePath, null, SQLiteDatabase.OPEN_READWRITE).use { db ->
                fingerprints.forEach { db.delete("observations", "fingerprint=?", arrayOf(it)) }
                ids.forEach { db.delete("feedback", "id=?", arrayOf(it)) }
            }
            SafetyResults.clear()
            val edit = settings.edit().clear()
            for ((key, value) in before) when (value) {
                is Boolean -> edit.putBoolean(key, value)
                is String -> edit.putString(key, value)
                is Int -> edit.putInt(key, value)
                is Long -> edit.putLong(key, value)
                is Float -> edit.putFloat(key, value)
            }
            edit.commit()
            test.runOnMainSync {
                if (wasMonitoring) context.startForegroundService(Intent(context, TsanetCaptureService::class.java))
            }
        }
    }
}
