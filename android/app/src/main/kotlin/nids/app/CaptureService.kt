package nids.app

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.Service
import android.content.Intent
import android.os.IBinder
import android.os.SystemClock
import nids.core.*
import org.json.JSONObject
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

object Live {
    @Volatile var running=false
    @Volatile var status="idle"
    @Volatile var packets=0L
    @Volatile var frames=0L
    @Volatile var malformed=0L
    @Volatile var unsupported=0L
    @Volatile var fragments=0L
    @Volatile var attributed=0L
    @Volatile var attributionStatus="not sampled"
    @Volatile var inferences=0L
    @Volatile var alerts=0L
    @Volatile var deviceAlarms=0L
    @Volatile var activeFlows=0
    @Volatile var msPerWindow=0.0
    @Volatile var lastPack=""
    @Volatile var session=""
    @Volatile var captureSeconds=0.0
    val recent=ArrayDeque<String>()
}

class CaptureService : Service() {
    @Volatile private var proc: Process?=null
    @Volatile private var stopping=false
    private val gate=Any()
    override fun onBind(i: Intent?): IBinder?=null
    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if(intent?.action==ACTION_STOP) { stopping=true; proc?.destroy(); stopSelf(); return START_NOT_STICKY }
        if(LearnedLive.running){stopSelf();return START_NOT_STICKY}
        if(Live.running) return START_NOT_STICKY
        val nm=getSystemService(NotificationManager::class.java)
        nm.createNotificationChannel(NotificationChannel("nids","NIDS",NotificationManager.IMPORTANCE_LOW))
        startForeground(1,Notification.Builder(this,"nids").setContentTitle("NIDS research monitor")
            .setContentText("Local observation; alerts are unconfirmed").setSmallIcon(android.R.drawable.ic_lock_idle_alarm).build())
        stopping=false; Live.running=true
        val model=intent?.getStringExtra("model") ?: "model_fp32.tflite"
        Thread({ loop(model) },"nids-capture").start()
        return START_NOT_STICKY
    }
    private fun loop(model: String) {
        var journal: SessionLog?=null
        var engine: StreamEngine?=null
        var scorer: TfliteScorer?=null
        val timer=Executors.newSingleThreadScheduledExecutor()
        val ownerTimer=Executors.newSingleThreadScheduledExecutor()
        val owners=UidResolver(this)
        val stderr=StringBuffer()
        var captureStart=0L
        var end="capture process ended unexpectedly"
        try {
            Live.captureSeconds=0.0
            Live.packets=0; Live.frames=0; Live.inferences=0; Live.alerts=0; Live.deviceAlarms=0
            Live.attributed=0; Live.lastPack=""; Live.malformed=0; Live.unsupported=0; Live.fragments=0
            synchronized(Live.recent) { Live.recent.clear() }
            val log=SessionLog(this,model); journal=log; Live.session=log.id
            log.health("session_start")
            Live.status="checking model and replay parity..."
            val selftest=SelfTest.run(this,model)
            log.health("self_test_pass",selftest)
            require(!stopping) { "stopped during self-test" }
            val rc=RuntimeConfig.parse(assets.open("runtime_config.txt").bufferedReader().use { it.readText() })
            val sc=TfliteScorer(this,model); scorer=sc
            val eng=StreamEngine(rc,sc,batchSize=1); engine=eng
            val collector=EvidenceCollector(rc)
            fun record(events: List<Event>) {
                for(e in events) {
                    val j=JSONObject(e.toJson())
                    if(e.type=="flow_alert") {
                        val attribution=owners.lookup(e)
                        j.put("attribution",attribution)
                        if(attribution.optString("status")=="best_effort") Live.attributed++
                    }
                    log.write("alerts.jsonl",j)
                    collector.onEvent(e)?.let {
                        log.write("evidence_packs.jsonl",JSONObject(it))
                        Live.lastPack=it
                    }
                    synchronized(Live.recent) { Live.recent.addFirst(j.toString()); while(Live.recent.size>30) Live.recent.removeLast() }
                }
            }
            recorder={ record(it) }
            Live.status="starting root capture..."
            val p=ProcessBuilder("su","-c","exec $TCPDUMP -i any -U -s 300 -w -").start(); proc=p
            Thread { try { p.errorStream.bufferedReader().useLines { ls -> ls.forEach { if(stderr.length<4096) stderr.append(it).append(' ') } } } catch(_: Exception) {} }.apply { isDaemon=true; start() }
            ownerTimer.scheduleWithFixedDelay({ if(!stopping) owners.refresh() },0,3,TimeUnit.SECONDS)
            val rd=PcapStreamReader(p.inputStream.buffered(65536))
            val clockWall=System.currentTimeMillis()/1000.0
            val clockMono=SystemClock.elapsedRealtime(); captureStart=clockMono
            log.health("capture_started", "pcap header validated")
            var lastHealth=clockMono
            timer.scheduleWithFixedDelay({
                synchronized(gate) {
                    try {
                        if(!stopping) {
                            record(eng.tick(clockWall+(SystemClock.elapsedRealtime()-clockMono)/1000.0))
                            publish(eng); Live.attributionStatus=owners.status
                            Live.captureSeconds=(SystemClock.elapsedRealtime()-clockMono)/1000.0
                            if(SystemClock.elapsedRealtime()-lastHealth>=60000) { log.health("heartbeat"); lastHealth=SystemClock.elapsedRealtime() }
                        }
                    } catch(e: Exception) { end="timer fault: ${e.message}"; stopping=true; p.destroy() }
                }
            },1,1,TimeUnit.SECONDS)
            Live.status="monitoring; experimental alerts, nothing blocked"
            while(!stopping) {
                val fr=rd.next() ?: break
                synchronized(gate) { record(eng.feedRaw(fr.data,fr.linktype,fr.ts)); publish(eng) }
            }
            if(stopping && !end.startsWith("timer fault")) end="stopped by user"
        } catch(e: Exception) { end=if(stopping) "stopped by user" else "monitor fault: ${e.javaClass.simpleName}: ${e.message}" }
        finally {
            stopping=true; timer.shutdownNow(); ownerTimer.shutdownNow()
            synchronized(gate) {
                try { engine?.let { recorder?.invoke(it.finish()); publish(it) } }
                catch(e: Exception) { end += "; finalization fault: ${e.message}" }
                scorer?.close()
                proc?.destroy(); try { proc?.inputStream?.close() } catch(_: Exception) {}
                if(captureStart>0) Live.captureSeconds=(SystemClock.elapsedRealtime()-captureStart)/1000.0
                Live.running=false; Live.status=end
                try { journal?.health("session_end",end+"; tcpdump: "+stderr.toString().take(4096)) } catch(e: Exception) { Live.status += "; log failure: ${e.message}" }
            }
            stopForeground(STOP_FOREGROUND_REMOVE); stopSelf()
        }
    }
    private var recorder: ((List<Event>)->Unit)?=null
    private fun publish(e: StreamEngine) {
        Live.packets=e.packets; Live.inferences=e.inferences; Live.alerts=e.alerts; Live.deviceAlarms=e.deviceAlarms
        Live.activeFlows=e.activeFlows; Live.frames=e.parseStats.frames; Live.malformed=e.parseStats.malformed
        Live.unsupported=e.parseStats.unsupportedLink; Live.fragments=e.parseStats.fragSkipped
        Live.msPerWindow=if(e.inferences>0) e.inferenceNanos/1e6/e.inferences else 0.0
    }
    override fun onDestroy() { stopping=true; proc?.destroy(); try { proc?.inputStream?.close() } catch(_: Exception) {}; super.onDestroy() }
    companion object {
        const val ACTION_STOP="nids.app.STOP"
        const val TCPDUMP="/data/local/tmp/tcpdump"
    }
}
