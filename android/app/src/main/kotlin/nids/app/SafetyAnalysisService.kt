package nids.app

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import org.json.JSONObject
import java.util.UUID
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger

/** Keeps message analysis and its persisted explanation queue alive independently of capture. */
class SafetyAnalysisService: Service() {
    private val ui = Handler(Looper.getMainLooper())
    private val active = AtomicInteger()
    private val executor = ThreadPoolExecutor(1, 1, 0, TimeUnit.SECONDS, ArrayBlockingQueue<Runnable>(16))
    override fun onBind(intent: Intent?): IBinder? = null

    override fun onCreate() {
        super.onCreate()
        val manager = getSystemService(NotificationManager::class.java)
        manager.createNotificationChannel(NotificationChannel("safety_checks", "Message and link checks", NotificationManager.IMPORTANCE_LOW))
        val open = PendingIntent.getActivity(this, 3, Intent(this, LearnedNetworkActivity::class.java),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE)
        startForeground(3, Notification.Builder(this, "safety_checks").setSmallIcon(android.R.drawable.ic_lock_idle_lock)
            .setContentTitle("Rakshak is checking locally").setContentText("Preparing message or link advice")
            .setContentIntent(open).setOngoing(true).build())
        if (!LlamaLive.running) ObservationStore.recoverQueue(this)
        ObservationStore.recoverInterruptedSafety(this)
        ui.post(idleCheck)
    }

    private val idleCheck = object: Runnable {
        override fun run() {
            AutomaticExplanations.pump(applicationContext)
            if (active.get() == 0 && ObservationStore.queuedCount(this@SafetyAnalysisService) == 0L && !LlamaLive.running) {
                stopForeground(STOP_FOREGROUND_REMOVE)
                stopSelf()
            } else ui.postDelayed(this, 2000)
        }
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val input = intent?.getStringExtra("input")
        if (input == null) return START_NOT_STICKY
        val domain = intent.getStringExtra("domain") ?: "message"
        val source = intent.getStringExtra("source") ?: "manual"
        val sender = intent.getStringExtra("sender")
        val id = intent.getStringExtra("request_id") ?: UUID.randomUUID().toString()
        val received = intent.getLongExtra("received_ms", System.currentTimeMillis())
        val generation = SafetyControls.generation(this)
        intent.removeExtra("input")
        intent.removeExtra("sender")
        if (source == "incoming" && !SafetyControls.enabled(this, SafetyControls.INCOMING)) return START_NOT_STICKY
        active.incrementAndGet()
        try {
            executor.execute {
                var previous: JSONObject? = null
                try {
                    val final = SafetyPipeline.analyze(this, input, domain, sender) { early ->
                        previous = early
                        publish(early, id, received, generation, source)
                    }
                    if (SafetyControls.generation(this) != generation) {
                        finishCancelled(previous, id, received, source)
                        if (source != "incoming") SafetyResults.put(id, JSONObject().put("analysis_status", "cancelled"))
                        return@execute
                    }
                    if (received <= getSharedPreferences("background_monitor", MODE_PRIVATE).getLong("history_cleared_ms", 0L)) return@execute
                    if (source != "incoming") SafetyResults.put(id, final)
                    publish(final, id, received, generation, source)
                    if (SafetyControls.generation(this) == generation &&
                        received > getSharedPreferences("background_monitor", MODE_PRIVATE).getLong("history_cleared_ms", 0)) {
                        val prefs = SafetyControls.preferences(this)
                        if (prefs.getString("last_request_id", null) == id) prefs.edit()
                            .putString("last_result", final.toString()).putString("last_state", "completed").apply()
                    }
                } catch (_: Exception) {
                    if (received <= getSharedPreferences("background_monitor", MODE_PRIVATE).getLong("history_cleared_ms", 0L)) return@execute
                    if (SafetyControls.generation(this) != generation) {
                        finishCancelled(previous, id, received, source)
                        if (source != "incoming") SafetyResults.put(id, JSONObject().put("analysis_status", "cancelled"))
                        return@execute
                    }
                    val failure = previous ?: JSONObject().put("schema", SafetyNote.VERSION).put("domain", domain)
                        .put("risk_level", "suspicious").put("evidence_codes", org.json.JSONArray())
                    failure.put("analysis_status", "failed").put("phase", "final")
                    if (source != "incoming") SafetyResults.put(id, failure)
                    publish(failure, id, received, generation, source)
                    val prefs = SafetyControls.preferences(this)
                    if (prefs.getString("last_request_id", null) == id)
                        prefs.edit().putString("last_result", failure.toString()).putString("last_state", "failed").apply()
                } finally { active.decrementAndGet() }
            }
        } catch (_: java.util.concurrent.RejectedExecutionException) {
            active.decrementAndGet()
            if (source != "incoming") SafetyResults.put(id, JSONObject().put("analysis_status", "busy"))
            SafetyControls.preferences(this).edit().putString("last_state", "busy").apply()
        }
        return START_NOT_STICKY
    }

    private fun finishCancelled(previous: JSONObject?, id: String, received: Long, source: String) {
        if (previous == null) return
        val evidence = JSONObject(previous.toString()).put("phase", "cancelled")
            .put("analysis_status", "partial").put("tier2_status", "cancelled_settings_changed")
        publish(evidence, id, received, SafetyControls.generation(this), source)
    }

    private fun publish(evidence: JSONObject, id: String, received: Long, generation: Long, source: String) {
        if (SafetyControls.generation(this) != generation) return
        if (evidence.optString("risk_level") == "low") return
        evidence.put("fingerprint", "safety|" + id).put("decision_time_ms", received).put("input_source", source)
            .put("test_only", source.startsWith("integration_fixture"))
        val row = ObservationStore.recordCurrent(this, "safety", if (evidence.optString("phase") == "final") 1L else 0L, evidence) ?: return
        ui.post {
            // Read again so clearing or a newer revision wins over a queued notification.
            val current = ObservationStore.get(this, row.getString("id")) ?: return@post
            ObservationNotifications.show(this, current)
            AutomaticExplanations.pump(applicationContext)
        }
    }

    override fun onDestroy() {
        ui.removeCallbacks(idleCheck)
        executor.shutdown()
        super.onDestroy()
    }

    companion object {
        fun submit(context: Context, input: String, domain: String, source: String = "manual", sender: String? = null): String {
            val id = UUID.randomUUID().toString()
            val prefs = SafetyControls.preferences(context)
            prefs.edit().putString("last_request_id", id).putString("last_state", "processing").remove("last_result").apply()
            val intent = Intent(context, SafetyAnalysisService::class.java).putExtra("input", input)
                .putExtra("domain", domain).putExtra("source", source).putExtra("sender", sender)
                .putExtra("request_id", id).putExtra("received_ms", System.currentTimeMillis())
            try { context.startForegroundService(intent) }
            catch (_: Exception) {
                prefs.edit().putString("last_state", "unavailable").apply()
                SafetyResults.put(id, JSONObject().put("analysis_status", "unavailable"))
            }
            return id
        }

        fun resume(context: Context) {
            if (!LlamaLive.running) ObservationStore.recoverQueue(context)
            if (ObservationStore.queuedCount(context) > 0 || ObservationStore.hasInterruptedSafety(context))
                context.startForegroundService(Intent(context, SafetyAnalysisService::class.java))
        }
    }
}
