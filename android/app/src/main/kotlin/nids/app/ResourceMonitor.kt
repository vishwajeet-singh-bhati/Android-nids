package nids.app

import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.os.BatteryManager
import android.os.Debug
import android.os.Process
import android.os.SystemClock
import org.json.JSONObject
import java.io.File
import java.util.concurrent.Executors
import java.util.concurrent.ScheduledExecutorService
import java.util.concurrent.TimeUnit

object LlamaLive {
    @Volatile var workerResident=false
    @Volatile var observationId=""
    @Volatile var workerResources=""
    @Volatile var stopAction: (() -> Unit)?=null
    @Volatile var running=false
    @Volatile var stage="Ready on device"
    @Volatile var startedMs=0L
}

/** Whole-process CPU/PSS and whole-device battery readings; never claims app-only energy. */
object ResourceMonitor {
    private val owners=HashSet<String>()
    private var scheduler: ScheduledExecutorService?=null
    private var previousCpu=0L
    private var previousTime=0L
    @Volatile var latest="{}";private set
    @Volatile var peakPssKib=0;private set
    fun captureNow(context: Context){sample(context.applicationContext)}
    @Synchronized fun acquire(context: Context,owner: String){
        owners.add(owner)
        if(scheduler!=null)return
        val app=context.applicationContext
        scheduler=Executors.newSingleThreadScheduledExecutor{r -> Thread(r,"nids-resource-sampler").apply{isDaemon=true}}
        val period=if(android.os.Build.VERSION.SDK_INT>=28 && android.app.Application.getProcessName().endsWith(":llama"))1L else 5L
        scheduler!!.scheduleWithFixedDelay({try{sample(app)}catch(_: Exception){}},0,period,TimeUnit.SECONDS)
    }
    @Synchronized fun release(owner: String){owners.remove(owner);if(owners.isEmpty()){scheduler?.shutdown();scheduler=null}}
    @Synchronized private fun sample(c: Context){
        Process.setThreadPriority(Process.THREAD_PRIORITY_BACKGROUND)
        val now=SystemClock.elapsedRealtime();val cpu=Process.getElapsedCpuTime();val memory=Debug.MemoryInfo();Debug.getMemoryInfo(memory)
        peakPssKib=maxOf(peakPssKib,memory.totalPss)
        val worker=try{JSONObject(LlamaLive.workerResources)}catch(_: Exception){JSONObject()}
        val workerPss=if(LlamaLive.running || LlamaLive.workerResident)worker.optInt("app_pss_kib") else 0
        val processName=if(android.os.Build.VERSION.SDK_INT>=28)android.app.Application.getProcessName() else String(File("/proc/self/cmdline").readBytes()).trimEnd('\u0000')
        val battery=c.getSystemService(BatteryManager::class.java);val intent=c.registerReceiver(null,IntentFilter(Intent.ACTION_BATTERY_CHANGED))
        val mode=if(LlamaLive.running){if(LearnedLive.running)"monitoring+llama" else "llama"}else if(LlamaLive.workerResident){if(LearnedLive.running)"monitoring+llama_warm" else "llama_warm"}else if(LearnedLive.running)"monitoring" else "paused"
        val thermal=if(android.os.Build.VERSION.SDK_INT>=29)c.getSystemService(android.os.PowerManager::class.java).currentThermalStatus else -1
        val row=JSONObject().put("process_id",Process.myPid()).put("process_name",processName).put("combined_app_pss_kib",memory.totalPss+workerPss).put("llama_worker_pss_kib",workerPss).put("packets_observed",LearnedLive.packets).put("model_checks",LearnedLive.inferences).put("capture_queue_drops",LearnedLive.queueDrops).put("capture_queue_depth",LearnedLive.queueDepth).put("thermal_status",thermal).put("time_ms",System.currentTimeMillis()).put("elapsed_ms",now).put("mode",mode).put("llama_stage",LlamaLive.stage).put("app_pss_kib",memory.totalPss).put("app_private_dirty_kib",memory.totalPrivateDirty).put("native_heap_allocated_bytes",Debug.getNativeHeapAllocatedSize()).put("process_cpu_ms",cpu).put("battery_percent",intent?.getIntExtra(BatteryManager.EXTRA_LEVEL,-1) ?: -1).put("plugged",intent?.getIntExtra(BatteryManager.EXTRA_PLUGGED,-1) ?: -1).put("battery_temperature_c",(intent?.getIntExtra(BatteryManager.EXTRA_TEMPERATURE,0) ?: 0)/10.0).put("battery_voltage_mv",intent?.getIntExtra(BatteryManager.EXTRA_VOLTAGE,-1) ?: -1)
        if(previousTime>0 && now>previousTime)row.put("app_cpu_one_core_percent",100.0*(cpu-previousCpu)/(now-previousTime))
        fun property(name: String,key: Int){val value=battery.getIntProperty(key);if(value!=Int.MIN_VALUE)row.put(name,value)}
        property("battery_charge_uah",BatteryManager.BATTERY_PROPERTY_CHARGE_COUNTER)
        property("battery_current_ua_raw",BatteryManager.BATTERY_PROPERTY_CURRENT_NOW)
        row.put("battery_scope","whole device; includes screen, radios and other apps").put("cpu_scope","app process; root collector measured separately")
        previousCpu=cpu;previousTime=now;latest=row.toString()
        val file=File(c.filesDir,if(processName.endsWith(":llama"))"resources_llama_v1.jsonl" else "resources_v1.jsonl")
        if(file.length()>2_000_000){val old=File(c.filesDir,file.name+".1");old.delete();check(file.renameTo(old))}
        file.appendText(latest+"\n")
    }
}
