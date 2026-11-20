package nids.app
import android.app.*
import android.content.Intent
import android.os.IBinder
import android.os.SystemClock
import nids.core.*
import org.json.JSONObject
import java.io.File
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicLong

object LearnedLive {
 @Volatile var running=false
 @Volatile var status="Paused"
 @Volatile var packets=0L
 @Volatile var inferences=0L
 @Volatile var warnings=0L
 @Volatile var lastEvidence=""
 @Volatile var seconds=0.0
 @Volatile var queueDepth=0
 @Volatile var queuePeak=0
 @Volatile var queueDrops=0L
 @Volatile var quality="Not monitoring"
 @Volatile var behaviorSnapshot="{}"
}
class ShortFlowCaptureService : Service() {
 @Volatile private var process: Process?=null
 @Volatile private var stopping=false
 override fun onBind(intent: Intent?): IBinder?=null
 override fun onStartCommand(intent: Intent?,flags: Int,startId: Int): Int {
  if(intent?.action==STOP){stopping=true;process?.destroy();stopSelf();return START_NOT_STICKY}
  if(Live.running){stopSelf();return START_NOT_STICKY}
  if(LearnedLive.running)return START_NOT_STICKY
  val manager=getSystemService(NotificationManager::class.java)
  manager.createNotificationChannel(NotificationChannel("learned_network","Local network monitoring",NotificationManager.IMPORTANCE_LOW))
  val open=PendingIntent.getActivity(this,0,Intent(this,LearnedNetworkActivity::class.java),PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE)
  startForeground(2,Notification.Builder(this,"learned_network").setContentTitle("NIDS · monitoring locally").setContentText("Traffic patterns, local explanations and feedback").setContentIntent(open).setOngoing(true).setSmallIcon(android.R.drawable.ic_lock_idle_alarm).build())
  stopping=false;LearnedLive.running=true
  Thread({monitor(intent?.getBooleanExtra("diagnostic",false)==true)},"network-analysis").start()
  return START_NOT_STICKY
 }
 @Synchronized private fun log(json: JSONObject){
  val file=File(filesDir,"learned_network.jsonl")
  if(file.length()>2_000_000){val old=File(filesDir,"learned_network.jsonl.1");old.delete();check(file.renameTo(old))}
  file.appendText(json.toString()+"\n")
 }
 private fun monitor(diagnostic: Boolean){
  android.os.Process.setThreadPriority(android.os.Process.THREAD_PRIORITY_BACKGROUND)
  ResourceMonitor.acquire(this,"monitor")
  val started=SystemClock.elapsedRealtime();val cpuStart=android.os.Process.getElapsedCpuTime()
  val timer=Executors.newSingleThreadScheduledExecutor();val parser=ParseStats();val stderr=StringBuffer()
  val queue=ArrayBlockingQueue<ParsedPacket>(4096);val captured=AtomicLong();val drops=AtomicLong()
  var readerThread: Thread?=null;var engine: ShortFlowMonitor?=null;var behavior: ShadowBehaviorMonitor?=null
  val readerDone=java.util.concurrent.atomic.AtomicBoolean(false);val readerError=java.util.concurrent.atomic.AtomicReference<String>("")
  val traceId=System.currentTimeMillis();val packetTrace=if(diagnostic)File(filesDir,"learned_packets_$traceId.tsv").bufferedWriter() else null
  var traced=0;var appliedDrops=0L;var lastFeatureResets=0L
  val qualityUntil=AtomicLong(0);val inbox=PatternInbox(this);val attribution=UidResolver(this);val ownerTimer=Executors.newSingleThreadScheduledExecutor()
  try{
   if(!diagnostic){ObservationStore.migrate(this);ObservationStore.recoverQueue(this)}
   ownerTimer.scheduleWithFixedDelay({attribution.refresh()},0,3,TimeUnit.SECONDS)
   LearnedLive.packets=0;LearnedLive.inferences=0;LearnedLive.warnings=0;LearnedLive.seconds=0.0;LearnedLive.queueDepth=0;LearnedLive.queuePeak=0;LearnedLive.queueDrops=0;LearnedLive.lastEvidence="";LearnedLive.quality="Checking models";LearnedLive.status="Starting"
   LearnedShortFlowScorer(this,if(diagnostic)File(filesDir,"learned_score_$traceId.jsonl") else null).use{scorer ->
    val detector=ShortFlowMonitor(scorer,scorer.threshold);engine=detector
    try{
     behavior=ShadowBehaviorMonitor(this,if(diagnostic)File(filesDir,"behavior_score_$traceId.jsonl") else null)
     log(JSONObject().put("event","behavior_start").put("mode","experimental_pattern_evidence").put("time_ms",System.currentTimeMillis()).put("model_sha256",behavior!!.manifest.getString("model_sha256")).put("startup_numeric_checks",32))
    }catch(e: Exception){log(JSONObject().put("event","behavior_error").put("error",e.toString()))}
    log(JSONObject().put("event","session_start").put("time_ms",System.currentTimeMillis()).put("diagnostic_mode",diagnostic).put("diagnostic_id",if(diagnostic)traceId else 0).put("model_sha256",scorer.manifest.getString("model_sha256")).put("threshold_logit",scorer.threshold).put("model_threads",1).put("worker_nice",10).put("queue_capacity",4096).put("evidence_batch_seconds",5))
    require(!stopping)
    val p=ProcessBuilder("su","-c","exec nice -n 10 ${CaptureService.TCPDUMP} -i any -U -s 96 -w -").start();process=p
    Thread{try{p.errorStream.bufferedReader().useLines{lines -> lines.forEach{if(stderr.length<4096)stderr.append(it).append(' ')}}}catch(_: Exception){}}.apply{isDaemon=true;start()}
    readerThread=Thread({
     android.os.Process.setThreadPriority(android.os.Process.THREAD_PRIORITY_BACKGROUND)
     try{
      val reader=PcapStreamReader(p.inputStream.buffered(65536))
      while(!stopping){
       val frame=reader.next() ?: break
       val packet=PacketParser.decode(frame.data,frame.linktype,frame.ts,0,setOf(53,5353),parser) ?: continue
       captured.incrementAndGet()
       if(!queue.offer(packet))drops.incrementAndGet()
       LearnedLive.queuePeak=maxOf(LearnedLive.queuePeak,queue.size)
      }
     }catch(e: Exception){if(!stopping)readerError.set(e.toString())}finally{readerDone.set(true)}
    },"network-collector-reader").apply{isDaemon=true;start()}
    LearnedLive.status="Monitoring";LearnedLive.quality="Observing · detection remains experimental"
    if(diagnostic)timer.schedule({stopping=true;process?.destroy()},90,TimeUnit.SECONDS)
    timer.scheduleWithFixedDelay({try{
     val b=behavior?.telemetry();LearnedLive.behaviorSnapshot=b?.toString() ?: "{}"
     val healthy=SystemClock.elapsedRealtime()>=qualityUntil.get()
     LearnedLive.quality=if(!healthy)"Limited coverage · recovering from skipped data" else if(b==null || b.optString("runtime_error").isNotEmpty())"Connection checks active · time-window model unavailable" else if(SystemClock.elapsedRealtime()-started<60000)"Building traffic context · connection checks active" else "Observing · detection remains experimental"
     if(!diagnostic){
      for(observation in inbox.flush(b,healthy,behavior?.feedbackExample(),SystemClock.elapsedRealtime()-started>=60000)){
       LearnedLive.lastEvidence=observation.toString();ObservationNotifications.show(this,observation)
       log(JSONObject().put("event","pattern_observation").put("observation_id",observation.getString("id")).put("revision",observation.getInt("revision")).put("kind",observation.getString("kind")).put("time_ms",observation.getLong("time_ms")))
      }
      AutomaticExplanations.pump(applicationContext)
     }
    }catch(e: Exception){LearnedLive.quality="Observation storage unavailable";log(JSONObject().put("event","observation_error").put("error",e.toString()))}},5,5,TimeUnit.SECONDS)
    timer.scheduleWithFixedDelay({try{
     LearnedLive.seconds=(SystemClock.elapsedRealtime()-started)/1000.0
     log(JSONObject().put("event","heartbeat").put("time_ms",System.currentTimeMillis()).put("packets",LearnedLive.packets).put("inferences",LearnedLive.inferences).put("warnings",LearnedLive.warnings).put("queue_drops",drops.get()).put("queue_depth",queue.size).put("queue_peak",LearnedLive.queuePeak).put("feature_resets",detector.featureResets).put("flow_evictions",detector.evictions).put("behavior",behavior?.telemetry()))
    }catch(_: Exception){}},30,30,TimeUnit.SECONDS)
    while(!stopping){
     val packet=queue.poll(250,TimeUnit.MILLISECONDS)
     LearnedLive.packets=captured.get();LearnedLive.queueDepth=queue.size;LearnedLive.queueDrops=drops.get()
     if(packet==null){if(readerDone.get())break;continue}
     if(drops.get()!=appliedDrops){appliedDrops=drops.get();detector.invalidate(packet.ts);behavior?.invalidateCapture();qualityUntil.set(SystemClock.elapsedRealtime()+60000)}
     if(packetTrace!=null && traced++<100000){packetTrace.write(listOf(packet.ts,packet.ipProto,packet.srcIp,packet.dstIp,packet.sport,packet.dport,packet.category,packet.tcpFlags,packet.seq,packet.payloadLen).joinToString("\t"));packetTrace.newLine()}
     try{behavior?.feed(packet)}catch(e: Exception){log(JSONObject().put("event","behavior_error").put("error",e.toString()));try{behavior?.close()}catch(_: Exception){};behavior=null}
     detector.feed(packet)?.let{warning ->
      if(diagnostic)log(JSONObject().put("event","diagnostic_shortflow_warning").put("time_ms",(warning.ts*1000).toLong()).put("flow_index",warning.flowIndex).put("initiator",warning.initiator).put("responder",warning.responder).put("prefix_packets",warning.prefix).put("model_logit",warning.logit).put("threshold_logit",scorer.threshold).put("model_sha256",scorer.manifest.getString("model_sha256")))
      inbox.shortFlow(warning.logit,scorer.threshold,warning.prefix,scorer.lastPositiveFeatures,attribution.lookupFlow(packet.ipProto,warning.initiator,warning.responder))
     }
     if(detector.featureResets!=lastFeatureResets){lastFeatureResets=detector.featureResets;qualityUntil.set(SystemClock.elapsedRealtime()+60000)}
     LearnedLive.inferences=detector.inferences;LearnedLive.warnings=detector.warnings;LearnedLive.seconds=(SystemClock.elapsedRealtime()-started)/1000.0
    }
    require(readerError.get().isEmpty() || stopping){readerError.get()}
    LearnedLive.status=if(stopping)"Paused" else "Capture ended · restart monitoring"
   }
  }catch(e: Exception){LearnedLive.status=if(stopping)"Paused" else "Needs attention: ${e.message}"}
  finally{
   stopping=true;timer.shutdownNow();ownerTimer.shutdownNow();process?.destroy();try{process?.inputStream?.close()}catch(_: Exception){}
   readerThread?.join(1000)
   try{packetTrace?.close()}catch(_: Exception){}
   if(!diagnostic)try{for(row in inbox.flush(behavior?.telemetry(),SystemClock.elapsedRealtime()>=qualityUntil.get(),null,SystemClock.elapsedRealtime()-started>=60000))LearnedLive.lastEvidence=row.toString()}catch(_: Exception){}
   try{behavior?.close()}catch(_: Exception){}
   LearnedLive.running=false;LearnedLive.packets=captured.get();LearnedLive.quality="Not monitoring"
   try{log(JSONObject().put("event","session_end").put("time_ms",System.currentTimeMillis()).put("status",LearnedLive.status).put("packets",captured.get()).put("processed_packets",engine?.packets ?: 0).put("inferences",LearnedLive.inferences).put("warnings",LearnedLive.warnings).put("queue_drops",drops.get()).put("pending_packets_at_stop",queue.size).put("queue_peak",LearnedLive.queuePeak).put("process_cpu_ms",android.os.Process.getElapsedCpuTime()-cpuStart).put("elapsed_ms",SystemClock.elapsedRealtime()-started).put("model_inference_ms",(engine?.inferenceNanos ?: 0)/1e6).put("malformed",parser.malformed).put("capture_loss","kernel packet loss not measured").put("behavior",behavior?.telemetry()).put("tcpdump_stderr",stderr.toString()))}catch(_: Exception){}
   LlamaClient.releaseIfIdle();ResourceMonitor.release("monitor");stopForeground(STOP_FOREGROUND_REMOVE);stopSelf()
  }
 }
 override fun onDestroy(){stopping=true;process?.destroy();try{process?.inputStream?.close()}catch(_: Exception){};super.onDestroy()}
 companion object{const val STOP="nids.app.SHORTFLOW_STOP"}
}
