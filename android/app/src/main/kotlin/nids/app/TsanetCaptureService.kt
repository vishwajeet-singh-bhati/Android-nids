package nids.app

import android.app.*
import android.content.Context
import android.content.Intent
import android.os.IBinder
import android.os.SystemClock
import nids.authentication.AuthenticationEpisodePolicy
import nids.core.*
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong

/** Foreground capture with bounded queues; Llama runs separately from packet processing. */
class TsanetCaptureService: Service(){
    @Volatile private var stopping=false
    @Volatile private var stopRequested=false
    @Volatile private var capture: Process?=null
    override fun onBind(intent: Intent?): IBinder?=null
    override fun onStartCommand(intent: Intent?,flags: Int,startId: Int): Int{
        val preferences=getSharedPreferences("background_monitor",Context.MODE_PRIVATE)
        if(intent?.action==STOP){
            log(JSONObject().put("event","monitor_stop_requested").put("time_ms",System.currentTimeMillis())
                .put("source",intent.getStringExtra("stop_source") ?: "internal_stop_intent")
                .put("user_confirmed",intent.getBooleanExtra("user_confirmed",false)))
            preferences.edit().putBoolean("enabled",false).apply();stopRequested=true;stopping=true;capture?.destroy();stopSelf();return START_NOT_STICKY
        }
        if(intent==null && !preferences.getBoolean("enabled",false)){stopSelf();return START_NOT_STICKY}
        if(LearnedLive.running)return START_STICKY
        if(Live.running){stopSelf();return START_NOT_STICKY}
        preferences.edit().putBoolean("enabled",true).apply()
        val manager=getSystemService(NotificationManager::class.java)
        manager.createNotificationChannel(NotificationChannel("context_monitor_v1","Background network monitor",NotificationManager.IMPORTANCE_LOW))
        val open=PendingIntent.getActivity(this,0,Intent(this,LearnedNetworkActivity::class.java),PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE)
        startForeground(2,Notification.Builder(this,"context_monitor_v1").setContentTitle("Rakshak is monitoring locally")
            .setContentText("Connection history and automatic local explanations").setSmallIcon(android.R.drawable.ic_lock_idle_alarm)
            .setContentIntent(open).setOngoing(true).build())
        stopRequested=false;stopping=false;LearnedLive.running=true
        Thread({monitor()},"context-network-monitor").start()
        return START_STICKY
    }
    @Synchronized private fun log(row: JSONObject){
        val file=File(filesDir,"tsanet_monitor.jsonl")
        if(file.length()>4_000_000){val old=File(filesDir,"tsanet_monitor.jsonl.1");old.delete();check(file.renameTo(old))}
        file.appendText(row.toString()+"\n")
    }
    private fun monitor(){
        android.os.Process.setThreadPriority(android.os.Process.THREAD_PRIORITY_BACKGROUND)
        val begin=SystemClock.elapsedRealtime();val cpu=android.os.Process.getElapsedCpuTime()
        val queue=ArrayBlockingQueue<ParsedPacket>(4096)
        val packets=AtomicLong();val drops=AtomicLong();val done=AtomicBoolean()
        val parser=ParseStats();val watched=HashSet<String>();val deliveryClock=CaptureDeliveryClock()
        val owners=UidResolver(this)
        fun refreshAddresses(){
            val addresses=owners.watchedAddresses()
            if(addresses.isNotEmpty()){watched.clear();watched.addAll(addresses)}
        }
        val collector=AlignedTsanetCollector(watched)
        val preferences=getSharedPreferences("background_monitor",Context.MODE_PRIVATE)
        val authEpisodes=AuthenticationEpisodePolicy()
        var authWasEnabled=false
        val cachedOwners=LinkedHashMap<String,JSONObject>();val refreshed=HashMap<String,Double>()
        val orientations=HashMap<String,Pair<String,String>>()
        val pending=LinkedHashMap<Pair<String,Boolean>,Pair<Long,JSONObject>>()
        var reader: Thread?=null;var ownerThread: Thread?=null;var lastTick=0L;var lastFlush=0L;var lastHeartbeat=0L
        var appliedDrops=0L;var appliedLate=0L;var unhealthyUntil=0L;var lastAddressRefresh=0L
        var runtimeError="";var modelNanos=0L
        var diagnosticRows=0
        ResourceMonitor.acquire(this,"monitor")
        try{
            owners.refresh();refreshAddresses();check(watched.isNotEmpty()){"No local interface addresses available: ${owners.status}"}
            ObservationStore.migrate(this)
            if(!getSharedPreferences("background_monitor",Context.MODE_PRIVATE).getBoolean("include_device_local_alerts",false)){
                val localIds=ObservationStore.reclassifyDeviceLocal(this)
                android.os.Handler(android.os.Looper.getMainLooper()).post{
                    for(id in localIds)getSystemService(NotificationManager::class.java).cancel(id.hashCode())
                    if(LlamaLive.observationId in localIds)LlamaClient.cancel("Device-local activity moved to separate scope")
                }
            }
            ObservationStore.recoverQueue(this)
            LearnedLive.packets=0;LearnedLive.inferences=0;LearnedLive.warnings=0
            LearnedLive.queueDrops=0;LearnedLive.queueDepth=0;LearnedLive.queuePeak=0
            LearnedLive.localOnlyFlows=0;LearnedLive.lastLocalConnection=""
            LearnedLive.behaviorSnapshot="{}";LearnedLive.status="Starting";LearnedLive.quality="Checking v2 models"
            AlignedV2Scorer(this).use{scorer->
                log(JSONObject().put("event","session_start").put("time_ms",System.currentTimeMillis())
                    .put("model_sha256",scorer.gateManifest.getString("model_sha256"))
                    .put("diagnosis_model_sha256",scorer.diagnosisManifest.getString("model_sha256"))
                    .put("feature_contract_sha256",scorer.gateManifest.getString("feature_contract_sha256"))
                    .put("schema","phone-aligned-v2").put("history_scope","all observed completed flows incident to watched phone address")
                    .put("local_only_default","observed separately; not external-intrusion scored")
                    .put("history_window_seconds",300).put("flow_timeout_seconds",30).put("capture_snaplen",768)
                    .put("capture_immediate_mode",true).put("idle_delivery_grace_ms",2000)
                    .put("gate_threshold",scorer.policy.gateThreshold).put("type_score_cutoff",scorer.policy.typeCutoff)
                    .put("history_sample_fraction",1.0).put("lab_accuracy_is_device_accuracy",false)
                    .put("network_mode","passive_capture_and_warnings"))
                ownerThread=Thread({while(!stopping){owners.refresh();try{Thread.sleep(1000)}catch(_: InterruptedException){break}}},"socket-ownership").apply{isDaemon=true;start()}
                val p=ProcessBuilder("su","-c","exec nice -n 10 ${CaptureService.TCPDUMP} --immediate-mode -i any -U -s 768 -w -").start();capture=p
                Thread{try{p.errorStream.bufferedReader().useLines{lines->lines.take(40).forEach{log(JSONObject().put("event","capture_message").put("message",it.take(300)))}}}catch(_: Exception){}}.apply{isDaemon=true;start()}
                reader=Thread({
                    android.os.Process.setThreadPriority(android.os.Process.THREAD_PRIORITY_BACKGROUND)
                    try{
                        val stream=PcapStreamReader(p.inputStream.buffered(65536))
                        while(!stopping){
                            val frame=stream.next() ?: break
                            val packet=AlignedPacketParser.decode(frame,parser) ?: continue
                            if(packet.ipProto!=6 && packet.ipProto!=17)continue
                            packets.incrementAndGet();if(!queue.offer(packet))drops.incrementAndGet()
                            LearnedLive.queuePeak=maxOf(LearnedLive.queuePeak,queue.size)
                        }
                    }catch(e: Exception){if(!stopping)runtimeError=e.toString()}finally{done.set(true)}
                },"context-packet-reader").apply{isDaemon=true;start()}
                LearnedLive.status="Monitoring"
                fun inspect(view: AlignedSnapshot){
                    val snapshot=view.flow
                    val cached=cachedOwners.remove(snapshot.key);refreshed.remove(snapshot.key);orientations.remove(snapshot.key)
                    val localOnly=NetworkObservationPolicy.isDeviceLocal(snapshot.source,snapshot.destination)
                    val includeLocal=getSharedPreferences("background_monitor",Context.MODE_PRIVATE).getBoolean("include_device_local_alerts",false)
                    if(localOnly){
                        LearnedLive.localOnlyFlows++
                        LearnedLive.lastLocalConnection="${snapshot.source}:${snapshot.sourcePort} → ${snapshot.destination}:${snapshot.destinationPort} (${snapshot.packets} packets)"
                        log(JSONObject().put("event","device_local_flow").put("time_ms",System.currentTimeMillis())
                            .put("source",snapshot.source).put("sport",snapshot.sourcePort).put("destination",snapshot.destination).put("dport",snapshot.destinationPort)
                            .put("packets",snapshot.packets).put("model_evaluated",includeLocal).put("external_intrusion_assessed",false))
                        if(!includeLocal)return
                    }
                    val decision=scorer.score(view);LearnedLive.inferences++
                    val observedAt=SystemClock.elapsedRealtime()
                    val authEnabled=preferences.getBoolean(AuthenticationEpisodePolicy.PREF,false)
                    val captureHealthy=observedAt>=unhealthyUntil && drops.get()==appliedDrops && collector.late==appliedLate
                    val authReady=authEnabled && captureHealthy
                    if(authReady!=authWasEnabled){authEpisodes.clear();authWasEnabled=authReady}
                    val policy=if(authReady && !localOnly)authEpisodes.apply(decision.classId,observedAt/1000.0,
                        snapshot.start,view.watched,snapshot.source,snapshot.destination,snapshot.sourcePort,
                        snapshot.destinationPort,snapshot.protocol,view.context[112]>0,view.context[113]>0,snapshot.flow[29]>0)
                        else AuthenticationEpisodePolicy.Result(decision.classId,decision.flagged)
                    val category=policy.classId
                    val episodeWarning=policy.protocol!=null && policy.emit
                    if(preferences.getBoolean("validation_trace",false) && diagnosticRows++<2000){
                        File(filesDir,"tsanet_validation_trace.jsonl").appendText(JSONObject()
                            .put("time_ms",System.currentTimeMillis()).put("start",snapshot.start).put("end",snapshot.end)
                            .put("source",snapshot.source).put("sport",snapshot.sourcePort).put("destination",snapshot.destination)
                            .put("dport",snapshot.destinationPort).put("protocol",snapshot.protocol).put("class_id",decision.classId)
                            .put("alert_category",category).put("alert_emitted",policy.emit)
                            .put("auth_episode_connections",policy.connections).put("auth_episode_enabled",authReady)
                            .put("schema","phone-aligned-v2").put("watched",view.watched)
                            .put("flow",JSONArray(snapshot.flow.toList())).put("context",JSONArray(view.context.toList()))
                            .put("gate_score",decision.gateScore.toDouble()).put("flagged",decision.flagged)
                            .put("diagnosis_scores",JSONArray(decision.diagnosisScores.toList())).toString()+"\n")
                    }
                    if(!policy.emit)return
                    val fresh=owners.lookupFlow(snapshot.protocol,"${snapshot.source}:${snapshot.sourcePort}","${snapshot.destination}:${snapshot.destinationPort}")
                    val owner=if(snapshot.closeReason=="tuple_reused")JSONObject().put("status","unknown").put("direction",fresh.optString("direction","unknown"))
                        .put("app_label","App unknown").put("reason","Connection tuple changed before ownership could be established")
                        else TsanetExplanationFacts.ownerSnapshot(fresh,cached)
                    if(owner.optString("direction")=="unknown")owner.put("direction",if(snapshot.source==view.watched)"outgoing" else "incoming")
                    val incoming=owner.optString("direction")=="incoming"
                    val role=if(incoming)16 else 0
                    fun count(index: Int)=kotlin.math.round(kotlin.math.expm1(view.context[index].toDouble())).toInt().coerceAtLeast(0)
                    val historyAge=kotlin.math.expm1(view.context[114].toDouble())
                    val evidence=JSONObject().put("schema","tsanet_phone_evidence_v1")
                        .put("traffic_scope",if(localOnly)"device_local_experimental" else "external_network")
                        .put("class_id",category).put("suspected_pattern",TsanetExplanationFacts.classes[category])
                        .put("model_sha256",scorer.gateManifest.getString("model_sha256"))
                        .put("attribution",owner).put("flow_packets",snapshot.packets)
                        .put("flow_duration_seconds",kotlin.math.round((snapshot.end-snapshot.start)*1000)/1000)
                        .put("feature_schema","phone-aligned-v2").put("binary_flag",true)
                        .put("diagnosis_model_sha256",scorer.diagnosisManifest.getString("model_sha256"))
                        .put("gate_score",decision.gateScore.toDouble()).put("gate_threshold",scorer.policy.gateThreshold)
                        .put("gate_flagged",decision.flagged).put("baseline_class_id",decision.classId)
                        .put("diagnosis_scores",JSONArray(decision.diagnosisScores.toList()))
                        .put("diagnosis_confidence",decision.diagnosisConfidence.toDouble()).put("type_score_cutoff",scorer.policy.typeCutoff)
                        .put("diagnosis_error",decision.diagnosisError).put("diagnosis_available",decision.diagnosisScores.isNotEmpty())
                        .put("type_established",!episodeWarning && category in 1..6).put("diagnosis_never_vetoes_gate",true)
                        .put("prior_connections_5m",count(64+role))
                        .put("target_ports_5m",count(64+role+if(incoming)7 else 6))
                        .put("history_age_seconds",historyAge.toInt()).put("history_window_seconds",300)
                        .put("history_complete",historyAge>=299.9)
                        .put("capture_healthy",captureHealthy)
                        .put("flow_end_time_ms",(snapshot.end*1000).toLong()).put("flow_close_reason",snapshot.closeReason)
                        .put("decision_time_ms",(view.decisionTime*1000).toLong()).put("flow_features",JSONArray(snapshot.flow.toList()))
                        .put("context_features",JSONArray(view.context.toList()))
                        .put("remote_endpoints_sample",JSONArray().put(owner.optString("remote_endpoint","unknown")))
                    val key=if(episodeWarning){
                        val start=checkNotNull(policy.firstStart)
                        evidence.put("authentication_episode",JSONObject().put("protocol",policy.protocol)
                            .put("connections_in_window",policy.connections).put("window_seconds",AuthenticationEpisodePolicy.WINDOW_SECONDS)
                            .put("first_observed_connection_ms",(start*1000).toLong()).put("authentication_outcome_verified",false))
                        "auth-episode|${policy.protocol}|${snapshot.source}|${snapshot.destination}|${snapshot.destinationPort}|$start"
                    }else if(NetworkObservationPolicy.rejectedIncomingEvidence(evidence))NetworkObservationPolicy.rejectedFingerprint(evidence)
                    else "aligned-v2|$category|${owner.optInt("uid",-1)}|${owner.optString("direction","unknown")}|${System.currentTimeMillis()/60000}"+(if(localOnly)"|local-experimental" else "")
                    evidence.put("fingerprint",key).put("detector",if(episodeWarning)"authentication_episode_preview" else "phone_aligned_v2_gate_diagnosis")
                    if(ObservationStore.expectedRepeat(this,evidence))return
                    LearnedLive.warnings++
                    // Keep changed behavior separate from batches that feedback may mute at flush.
                    val pendingKey=Pair(key,NetworkObservationPolicy.expectedRepeatKey(evidence)!=null)
                    val previous=pending[pendingKey]
                    pending[pendingKey]=Pair((previous?.first ?: 0)+1,evidence)
                    log(JSONObject().put("event","model_flag").put("time_ms",System.currentTimeMillis()).put("evidence",evidence))
                }
                while(!stopping){
                    val packet=queue.poll(250,TimeUnit.MILLISECONDS)
                    val now=SystemClock.elapsedRealtime()
                    if(drops.get()!=appliedDrops){appliedDrops=drops.get();unhealthyUntil=now+300000}
                    if(packet!=null){
                        deliveryClock.received(packet.ts,now)
                        val key=TsanetFlowCollector.flowKey(packet.ipProto,packet.srcIp,packet.sport,packet.dstIp,packet.dport)
                        if(!orientations.containsKey(key)){cachedOwners.remove(key);refreshed.remove(key)}
                        val orientation=orientations.getOrPut(key){Pair("${packet.srcIp}:${packet.sport}","${packet.dstIp}:${packet.dport}")}
                        val interval=if(cachedOwners[key]?.optString("status")=="best_effort")2.0 else .25
                        if(packet.ts-(refreshed[key] ?: 0.0)>interval){
                            refreshed[key]=packet.ts
                            val owner=owners.lookupFlow(packet.ipProto,orientation.first,orientation.second)
                            if(owner.optString("status")=="best_effort" || !cachedOwners.containsKey(key))cachedOwners[key]=owner
                            while(cachedOwners.size>4096){val oldest=cachedOwners.keys.first();cachedOwners.remove(oldest);refreshed.remove(oldest);orientations.remove(oldest)}
                        }
                        collector.feed(packet).forEach{inspect(it)}
                    }else if(done.get())break
                    if(now-lastAddressRefresh>=5000){refreshAddresses();lastAddressRefresh=now}
                    if(now-lastTick>=1000){deliveryClock.advanceTo(now,queue.size)?.let{collector.advance(it).forEach{snapshot->inspect(snapshot)}};lastTick=now}
                    if(collector.late!=appliedLate){appliedLate=collector.late;unhealthyUntil=now+300000}
                    if(now-lastFlush>=5000){
                        for((count,evidence) in pending.values){
                            val row=ObservationStore.recordCurrent(this,"tsanet_pattern",count,evidence) ?: continue
                            LearnedLive.lastEvidence=row.toString();ObservationNotifications.show(this,row)
                        }
                        pending.clear();AutomaticExplanations.pump(applicationContext);lastFlush=now
                    }
                    LearnedLive.packets=packets.get();LearnedLive.queueDrops=drops.get();LearnedLive.queueDepth=queue.size
                    LearnedLive.seconds=(now-begin)/1000.0
                    LearnedLive.quality=if(now<unhealthyUntil)"Limited history after skipped traffic" else if(now-begin<300000)
                        "Monitoring · building recent connection history" else "Monitoring · local connection history ready"
                    if(now-lastHeartbeat>=30000){
                        log(JSONObject().put("event","heartbeat").put("time_ms",System.currentTimeMillis())
                            .put("packets",packets.get()).put("inferences",LearnedLive.inferences).put("flags",LearnedLive.warnings)
                            .put("local_only_flows",LearnedLive.localOnlyFlows).put("local_only_alerts_enabled",getSharedPreferences("background_monitor",Context.MODE_PRIVATE).getBoolean("include_device_local_alerts",false))
                            .put("schema","phone-aligned-v2").put("diagnosis_inferences",scorer.diagnosisInferences)
                            .put("auth_episode_enabled",preferences.getBoolean(AuthenticationEpisodePolicy.PREF,false))
                            .put("active_flows",collector.activeFlows).put("history_window_seconds",300)
                            .put("invalid_rate_flows",collector.invalidFlows).put("evictions",collector.flowEvictions)
                            .put("history_evictions",collector.historyEvictions).put("forced_reorder",collector.forcedReorder)
                            .put("late_packets",collector.late).put("queue_drops",drops.get()).put("queue_depth",queue.size)
                            .put("model_inference_ms",scorer.inferenceNanos/1e6).put("uptime_ms",now-begin))
                        lastHeartbeat=now
                    }
                }
                modelNanos=scorer.inferenceNanos
                if(runtimeError.isNotEmpty() && !stopping)error(runtimeError)
            }
            LearnedLive.status=if(stopping)"Paused" else "Capture ended · restart monitoring"
        }catch(e: Throwable){runtimeError=e.toString();LearnedLive.status="Needs attention: ${e.message}";log(JSONObject().put("event","runtime_error").put("error",runtimeError))}
        finally{
            val retry=!stopRequested && getSharedPreferences("background_monitor",Context.MODE_PRIVATE).getBoolean("enabled",false)
            stopping=true;capture?.destroy();try{capture?.inputStream?.close()}catch(_: Exception){}
            ownerThread?.interrupt();reader?.join(1000)
            for((count,evidence) in pending.values)try{ObservationStore.recordCurrent(this,"tsanet_pattern",count,evidence)}catch(_: Exception){}
            LearnedLive.running=false;LearnedLive.quality="Not monitoring"
            log(JSONObject().put("event","session_end").put("time_ms",System.currentTimeMillis())
                .put("packets",packets.get()).put("inferences",LearnedLive.inferences).put("flags",LearnedLive.warnings)
                .put("queue_drops",drops.get()).put("model_inference_ms",modelNanos/1e6)
                .put("cpu_ms",android.os.Process.getElapsedCpuTime()-cpu).put("runtime_error",runtimeError)
                .put("stop_requested",stopRequested).put("monitoring_enabled",preferences.getBoolean("enabled",false)))
            ResourceMonitor.release("monitor");LlamaClient.releaseIfIdle()
            if(retry){
                LearnedLive.status="Reconnecting";LearnedLive.quality="Monitoring interrupted · retrying locally"
                android.os.Handler(android.os.Looper.getMainLooper()).postDelayed({
                    if(!stopRequested && !LearnedLive.running){stopping=false;LearnedLive.running=true;Thread({monitor()},"context-monitor-retry").start()}
                },10000)
            }else{stopForeground(STOP_FOREGROUND_REMOVE);stopSelf()}
        }
    }
    override fun onDestroy(){
        log(JSONObject().put("event","monitor_service_destroyed").put("time_ms",System.currentTimeMillis())
            .put("stop_requested_before_destroy",stopRequested))
        stopRequested=true;stopping=true;capture?.destroy();super.onDestroy()
    }
    companion object{const val STOP="nids.app.CONTEXT_STOP"}
}
