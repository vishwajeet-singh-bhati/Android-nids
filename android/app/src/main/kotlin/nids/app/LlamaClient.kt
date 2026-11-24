package nids.app
import android.content.*
import android.os.*
import org.json.JSONObject

/** Isolated native runtime with a two-minute idle warm cache and a full-request watchdog. */
object LlamaClient {
 private val ui=Handler(Looper.getMainLooper())
 private var connection: ServiceConnection?=null
 private var remote: Messenger?=null
 private var finish: ((JSONObject?,String?)->Unit)?=null
 private var app: Context?=null
 private var bound=false
 private var sequence=0
 private var pending: JSONObject?=null
 private val timeout=Runnable{cancel("Local explanation timed out")}
 private val idleRelease=Runnable{if(!LlamaLive.running)closeConnection()}
 private fun closeConnection(){
  ui.removeCallbacks(idleRelease)
  try{if(bound && connection!=null)app?.unbindService(connection!!)}catch(_: Exception){}
  bound=false;connection=null;remote=null;LlamaLive.workerResident=false;LlamaLive.workerResources="";LlamaLive.stage="Ready on device"
 }
 private fun complete(result: JSONObject?,error: String?,keepWarm: Boolean){
  val callback=finish ?: run{if(!keepWarm)closeConnection();return}
  result?.put("client_elapsed_ms",SystemClock.elapsedRealtime()-LlamaLive.startedMs)
  finish=null;pending=null;ui.removeCallbacks(timeout);LlamaLive.running=false;LlamaLive.stopAction=null
  LlamaLive.stage=if(keepWarm)"Warm local model ready" else "Ready on device"
  ResourceMonitor.release("llama-client")
  if(keepWarm){LlamaLive.workerResident=true;ui.postDelayed(idleRelease,120000)}else closeConnection()
  callback(result,error)
 }
 private val replies=Messenger(Handler(Looper.getMainLooper()){message ->
  if(message.what==LlamaWorkerService.STATUS){
   if(bound && message.data.getInt("request_id")==sequence){LlamaLive.workerResources=message.data.getString("resources") ?: "";LlamaLive.workerResident=message.data.getBoolean("resident");if(LlamaLive.running)LlamaLive.stage=message.data.getString("stage") ?: "Explaining locally"}
  }else if(finish!=null && message.data.getInt("request_id")==sequence){
   when(message.what){
    LlamaWorkerService.RESULT->try{complete(JSONObject(message.data.getString("report")!!),null,true)}catch(e: Exception){complete(null,e.message,false)}
    LlamaWorkerService.FAILURE->complete(null,message.data.getString("error") ?: "Local model unavailable",false)
   }
  };true
 })
 private fun send(){
  val evidence=pending ?: return
  try{remote!!.send(Message.obtain(null,LlamaWorkerService.REQUEST).apply{replyTo=replies;data=Bundle().apply{putInt("request_id",sequence);putString("evidence",evidence.toString())}})}catch(e: Exception){complete(null,e.message,false)}
 }
 fun cancel(reason: String="Explanation cancelled"){
  try{remote?.send(Message.obtain(null,LlamaWorkerService.CANCEL))}catch(_: Exception){}
  complete(null,reason,false)
 }
 fun releaseIfIdle(){ui.post{if(!LlamaLive.running)closeConnection()}}
 fun explain(context: Context,evidence: JSONObject,callback: (JSONObject?,String?)->Unit){
  require(Looper.myLooper()==Looper.getMainLooper());require(!LlamaLive.running){"Another explanation is running"}
  ui.removeCallbacks(idleRelease);sequence++;app=context.applicationContext;finish=callback;pending=evidence
  LlamaLive.observationId=evidence.optString("id");LlamaLive.running=true;LlamaLive.stage=if(remote!=null)"Writing explanation" else "Preparing local model";LlamaLive.startedMs=SystemClock.elapsedRealtime();LlamaLive.stopAction={cancel()};ResourceMonitor.acquire(context,"llama-client");ui.postDelayed(timeout,150000)
  if(remote!=null && bound){send();return}
  val conn=object: ServiceConnection{
   override fun onServiceConnected(name: ComponentName,binder: IBinder){if(connection!==this)return;remote=Messenger(binder);send()}
   override fun onServiceDisconnected(name: ComponentName){if(connection===this)complete(null,"Local explanation process ended; monitoring continues",false)}
   override fun onBindingDied(name: ComponentName){if(connection===this)complete(null,"Local explanation process disconnected",false)}
  };connection=conn
  try{bound=app!!.bindService(Intent(context,LlamaWorkerService::class.java),conn,Context.BIND_AUTO_CREATE);if(!bound)complete(null,"Could not start local model",false)}catch(e: Exception){complete(null,e.message,false)}
 }
}
