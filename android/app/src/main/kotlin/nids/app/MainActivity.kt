package nids.app

import android.Manifest
import android.app.Activity
import android.content.Intent
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.widget.*
import org.json.JSONObject
import java.io.File
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

class MainActivity : Activity() {
    private lateinit var out: TextView
    private var model="model_fp32.tflite"
    private var report=""
    private val ui=Handler(Looper.getMainLooper())
    private val tick=object: Runnable { override fun run() { render(); ui.postDelayed(this,1000) } }
    override fun onCreate(b: Bundle?) {
        super.onCreate(b)
        if(!intent.getBooleanExtra("research",false)){startActivity(Intent(this,LearnedNetworkActivity::class.java));finish();return}
        if(android.os.Build.VERSION.SDK_INT>=33) requestPermissions(arrayOf(Manifest.permission.POST_NOTIFICATIONS),1)
        val col=LinearLayout(this).apply { orientation=LinearLayout.VERTICAL; setPadding(24,24,24,24) }
        fun btn(label: String, action: (Button)->Unit) {
            col.addView(Button(this).apply { text=label; setOnClickListener { action(this) } })
        }
        col.addView(TextView(this).apply { text="NIDS research monitor\nExperimental traffic warnings. An alert does not confirm an attack. Nothing is blocked."; textSize=16f })
        btn("Model: FP32 reference") { b ->
            if(!Live.running) {
                model=if(model.contains("fp32")) "model_int8_wonly.tflite" else "model_fp32.tflite"
                b.text=if(model.contains("fp32")) "Model: FP32 reference" else "Model: smaller candidate (requires validation)"
            }
        }
        btn("Run model self-test") { b ->
            if(!Live.running && b.isEnabled) {
                val selected=model; b.isEnabled=false; report="Checking model..."; render()
                Thread {
                    val result=try { SessionLog(this,selected); SelfTest.run(this,selected) } catch(e: Exception) { "SELF-TEST FAILED: ${e.message}" }
                    File(filesDir,"self_test.txt").writeText(result)
                    ui.post { report=result; b.isEnabled=true; render() }
                }.start()
            }
        }
        btn("Open learned network monitor") { startActivity(Intent(this,LearnedNetworkActivity::class.java)) }
        btn("Start local monitoring") {
            if(!Live.running) { report=""; startForegroundService(Intent(this,CaptureService::class.java).putExtra("model",model)) }
        }
        btn("Stop monitoring") { startService(Intent(this,CaptureService::class.java).setAction(CaptureService.ACTION_STOP)) }
        btn("Export diagnostic logs") {
            startActivityForResult(Intent(Intent.ACTION_CREATE_DOCUMENT).setType("application/zip").putExtra(Intent.EXTRA_TITLE,"nids-diagnostics.zip"),42)
        }
        out=TextView(this).apply { textSize=14f }
        col.addView(ScrollView(this).apply { addView(out) })
        setContentView(col)
    }
    override fun onResume() { super.onResume(); ui.post(tick) }
    override fun onPause() { ui.removeCallbacks(tick); super.onPause() }
    private fun render() {
        if(!::out.isInitialized) return
        out.text=if(report.isNotEmpty()) report else "Status: ${Live.status}\nObserved packets: ${Live.packets}\nTraffic warnings: ${Live.alerts}\nDevice warnings: ${Live.deviceAlarms}\nWarnings with a possible app owner: ${Live.attributed}\n\n" +
            (if(Live.deviceAlarms>0) "Some traffic resembled the training data's malware-associated patterns. This is unconfirmed. Review recently installed apps; the monitor cannot establish infection.\n\n" else "") +
            "Checks and logs stay on this phone. Diagnostic exports include network addresses and possible app names, but no packet payloads. Share them only with someone you trust."
    }
    @Deprecated("Activity result API")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode,resultCode,data)
        if(requestCode!=42 || resultCode!=RESULT_OK) return
        val uri=data?.data ?: return
        Thread {
            val result=try {
                contentResolver.openOutputStream(uri)!!.use { output -> ZipOutputStream(output).use { zip ->
                    for(base in listOf("sessions.jsonl","alerts.jsonl","evidence_packs.jsonl","self_test.txt","validation.json")) for(name in listOf(base,"$base.1")) {
                        val f=File(filesDir,name); if(f.exists()) { zip.putNextEntry(ZipEntry(name)); f.inputStream().use { it.copyTo(zip) }; zip.closeEntry() }
                    }
                    zip.putNextEntry(ZipEntry("model_manifest.json")); assets.open("model_manifest.json").use { it.copyTo(zip) }; zip.closeEntry()
                } }
                "Diagnostic export saved."
            } catch(e: Exception) { "Export failed: ${e.message}" }
            ui.post { report=result; render() }
        }.start()
    }
}
