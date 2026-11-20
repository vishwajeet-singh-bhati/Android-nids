package nids.app

import android.content.Context
import nids.core.BehaviorTimeline
import nids.core.BehaviorSnapshot
import nids.core.BehaviorConfirmation
import android.os.SystemClock
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicLong
import nids.core.ParsedPacket
import org.json.JSONObject
import org.pytorch.executorch.EValue
import org.pytorch.executorch.Module
import org.pytorch.executorch.Tensor
import java.io.File

/** Experimental learned behavior model; observations remain in shadow telemetry. */
class ShadowBehaviorMonitor(context: Context, trace: File?=null): AutoCloseable {
    val manifest=JSONObject(context.assets.open("behavior_manifest.json").bufferedReader().use{it.readText()})
    private val activity=BehaviorTimeline()
    private data class Arrival(val packet: ParsedPacket,val receivedMs: Long)
    private val queue=ArrayBlockingQueue<Arrival>(2048)
    private val drops=AtomicLong()
    @Volatile private var stopping=false
    @Volatile private var error=""
    private var appliedDrops=0L
    private var queuePeak=0
    private val traceWriter=trace?.bufferedWriter()
    private var traced=0
    private val confirmation=BehaviorConfirmation()
    private var confirmedWindows=0L
    private var confirmedExample=""
    private val buffer=Tensor.allocateFloatBuffer(27)
    private val inputs=arrayOf(EValue.from(Tensor.fromBlob(buffer,longArrayOf(1,27))))
    private val module: Module
    var snapshots=0L;private set
    var positiveWindows=0L;private set
    var suppressedWindows=0L;private set
    var inferenceNanos=0L;private set
    val featureResets get()=activity.featureResets
    init {
        val file=File(context.filesDir,"behavior_model.pte")
        val hash=manifest.getString("model_sha256")
        if(!file.exists() || LearnedShortFlowScorer.sha256(file)!=hash)
            context.assets.open("behavior_model.pte").use{input -> file.outputStream().use{input.copyTo(it)}}
        require(LearnedShortFlowScorer.sha256(file)==hash){"Behavior model integrity failure"}
        module=Module.load(file.absolutePath,Module.LOAD_MODE_MMAP,1)
        try {
            module.loadMethod("forward")
            val check=JSONObject(context.assets.open("behavior_selfcheck.json").bufferedReader().use{it.readText()})
            require(check.getString("model_sha256")==hash)
            val cases=check.getJSONArray("cases")
            for(i in 0 until cases.length()){
                val c=cases.getJSONObject(i);val a=c.getJSONArray("features")
                val actual=score(FloatArray(27){a.getDouble(it).toFloat()})
                require(kotlin.math.abs(actual-c.getDouble("expected_score"))<check.getDouble("absolute_tolerance")){"Behavior numeric self-check failure"}
            }
        }catch(e: Throwable){module.close();traceWriter?.close();throw e}
    }
    private fun score(features: FloatArray): Double {
        buffer.clear();buffer.put(features);buffer.rewind()
        return module.forward(*inputs)[0].toTensor().dataAsFloatArray[0].toDouble().also{require(it.isFinite())}
    }
    private fun evaluate(ready: List<BehaviorSnapshot>){
        for(snapshot in ready){
            val healthy=activity.healthy(snapshot.endSecond)
            if(!healthy){suppressedWindows++;confirmation.clear();continue}
            val start=System.nanoTime();val value=score(snapshot.features);inferenceNanos+=System.nanoTime()-start
            snapshots++;if(value>=0)positiveWindows++
            val confirmed=confirmation.accept(snapshot.host,snapshot.endSecond,value>=0)
            if(confirmed){confirmedWindows++;confirmedExample=JSONObject().put("feature_version","endpoint_bins_5_30_60_v1").put("model_sha256",manifest.getString("model_sha256")).put("features",org.json.JSONArray(snapshot.features.toList())).put("score",value).toString()}
            if(traceWriter!=null && traced++<10000){
                val row=JSONObject().put("host",snapshot.host).put("end_second",snapshot.endSecond).put("features",org.json.JSONArray(snapshot.features.toList())).put("score",value).put("confirmed",confirmed).put("scored_elapsed_ms",SystemClock.elapsedRealtime())
                traceWriter.write(row.toString());traceWriter.newLine()
            }
        }
    }
    private val worker=Thread({
        android.os.Process.setThreadPriority(android.os.Process.THREAD_PRIORITY_BACKGROUND)
        try{
            while(!stopping){
                val next=queue.poll(250,TimeUnit.MILLISECONDS)
                synchronized(this){
                    val lost=drops.get()
                    if(lost!=appliedDrops){activity.invalidate();confirmation.clear();appliedDrops=lost}
                    evaluate(if(next!=null)activity.push(next.packet,next.receivedMs) else activity.idle(SystemClock.elapsedRealtime()))
                }
            }
        }catch(e: InterruptedException){if(!stopping)error=e.toString()}
        catch(e: Exception){error=e.toString()}
        finally{module.close();traceWriter?.close()}
    },"behavior-shadow-worker").apply{isDaemon=true;start()}
    @Synchronized fun feedbackExample(): JSONObject?=confirmedExample.takeIf{it.isNotEmpty()}?.let{JSONObject(it)}
    fun invalidateCapture(){drops.incrementAndGet()}
    @Synchronized fun feed(packet: ParsedPacket){
        if(stopping || error.isNotEmpty() || packet.ipProto!=6 && packet.ipProto!=17)return
        if(!queue.offer(Arrival(packet,SystemClock.elapsedRealtime())))drops.incrementAndGet()
        queuePeak=maxOf(queuePeak,queue.size)
    }
    @Synchronized fun telemetry()=JSONObject().put("mode","experimental_pattern_evidence").put("runtime_error",error).put("snapshots",snapshots).put("positive_endpoint_windows",positiveWindows).put("confirmed_endpoint_windows",confirmedWindows).put("confirmation_state_resets",confirmation.stateResets).put("suppressed_windows",suppressedWindows).put("feature_resets",featureResets).put("inference_ms",inferenceNanos/1e6).put("queue_drops",drops.get()).put("queue_peak",queuePeak).put("late_packets",activity.latePackets).put("idle_closures",activity.idleClosures).put("bucket_closure","ordered consumer; 2-second monotonic idle grace; late arrivals abstain")
    override fun close(){stopping=true;worker.interrupt();worker.join(5000)}
}
