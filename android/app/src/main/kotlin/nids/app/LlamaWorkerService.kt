package nids.app
import android.app.Service
import android.content.Intent
import android.os.*
import org.json.JSONObject

/** One independent native runtime; cached weights are reused with fresh prompt context. */
class LlamaWorkerService: Service(){
 private val handler=Handler(Looper.getMainLooper())
 @Volatile private var busy=false
 @Volatile private var dying=false
 private var requestId=0
 private var caller: Messenger?=null
 private val release=Runnable{android.os.Process.killProcess(android.os.Process.myPid())}
 private fun exit(){dying=true;handler.postDelayed(release,300)}
 private fun send(code: Int,data: Bundle){data.putInt("request_id",requestId);try{caller?.send(Message.obtain(null,code).apply{this.data=data})}catch(_: Exception){}}
 private val status=object: Runnable{override fun run(){
  send(STATUS,Bundle().apply{putString("stage",LlamaLive.stage);putString("resources",ResourceMonitor.latest);putBoolean("resident",LlamaLive.workerResident)})
  if(!dying)handler.postDelayed(this,1000)
 }}
 private val receiver=Messenger(Handler(Looper.getMainLooper()){message ->
  when(message.what){
   REQUEST->{
    if(busy || dying){try{message.replyTo?.send(Message.obtain(null,FAILURE).apply{data=Bundle().apply{putInt("request_id",message.data.getInt("request_id"));putString("error","Local worker is restarting")}})}catch(_: Exception){}}
    else{
     busy=true;requestId=message.data.getInt("request_id");caller=message.replyTo
     val evidence=message.data.getString("evidence") ?: "{}"
     LlamaLive.workerResident=true
     Thread({
      try{
       val beforeCpu=android.os.Process.getElapsedCpuTime()
       val report=LocalExplainer(applicationContext).explain(JSONObject(evidence)).put("execution_process",":llama").put("worker_pid",android.os.Process.myPid()).put("worker_process_cpu_ms",android.os.Process.getElapsedCpuTime()-beforeCpu).put("worker_sampled_peak_pss_kib",ResourceMonitor.peakPssKib)
       val rss=try{java.io.File("/proc/self/status").readLines().first{it.startsWith("VmHWM:")}.trim().split(Regex("\\s+"))[1].toLong()}catch(_: Exception){-1L};report.put("worker_peak_rss_kib",rss)
       ResourceMonitor.acquire(applicationContext,"warm-cache");ResourceMonitor.captureNow(applicationContext)
       busy=false
       send(RESULT,Bundle().apply{putString("report",report.toString())})
      }catch(e: Exception){busy=false;send(FAILURE,Bundle().apply{putString("error",e.message ?: "Local explanation failed")});exit()}
     },"isolated-local-llama").start()
    }
   }
   CANCEL->{send(FAILURE,Bundle().apply{putString("error","Explanation cancelled")});exit()}
  };true
 })
 override fun onBind(intent: Intent?): IBinder{handler.post(status);return receiver.binder}
 override fun onUnbind(intent: Intent?): Boolean{handler.removeCallbacks(status);exit();return false}
 override fun onTrimMemory(level: Int){super.onTrimMemory(level);if(!busy && level>=TRIM_MEMORY_RUNNING_LOW)exit()}
 companion object{const val REQUEST=1;const val RESULT=3;const val FAILURE=4;const val CANCEL=5;const val STATUS=6}
}
