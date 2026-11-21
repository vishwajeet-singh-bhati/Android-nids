package nids.app

import android.app.Activity
import android.app.Instrumentation
import android.content.Context
import android.content.ContextWrapper
import android.content.Intent
import android.os.Bundle
import android.os.SystemClock
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

/** Isolated store fixtures and real IPC; never creates an attack or a live incident. */
class HybridPipelineValidation(private val test: Instrumentation,private val context: Context){
    private val directory=File(context.filesDir,"hybrid_validation_v1").apply{mkdirs()}
    private fun runtime(): JSONObject {
        val report=JSONObject().put("trials",JSONArray()).put("test_only",true).put("attack_detection_test",false)
        test.runOnMainSync{context.startForegroundService(Intent(context,TsanetCaptureService::class.java))}
        val until=SystemClock.elapsedRealtime()+40000
        while(!LearnedLive.running || LearnedLive.status!="Monitoring"){check(SystemClock.elapsedRealtime()<until);Thread.sleep(200)}
        // A clearly labelled transient preview verifies the real notification
        // body before Llama starts. It is never inserted into activity history.
        val previewEvidence=HybridFixtures.evidence(5,true)
        val preview=JSONObject().put("id","hybrid-preview-"+java.util.UUID.randomUUID()).put("revision",1)
            .put("title","TEST: explanation preview, no real incident").put("model_evidence",previewEvidence)
            .put("attribution",previewEvidence.getJSONObject("attribution")).put("explanation_status","queued")
        val manager=context.getSystemService(android.app.NotificationManager::class.java)
        try{
            val tick=SystemClock.elapsedRealtime();test.runOnMainSync{ObservationNotifications.show(context,preview)}
            val posted=manager.activeNotifications.first{it.id==preview.getString("id").hashCode()}
            check(posted.notification.extras.getCharSequence(android.app.Notification.EXTRA_BIG_TEXT).toString()==HybridActivityNote.display(preview))
            check(!LlamaLive.running)
            report.put("immediate_notification_content_verified",true).put("notification_post_and_query_ms",SystemClock.elapsedRealtime()-tick)
            report.put("notification_preview_labelled_test",true)
        }finally{manager.cancel(preview.getString("id").hashCode())}
        test.runOnMainSync{LlamaClient.releaseIfIdle()};Thread.sleep(1500)
        for((index,category) in listOf(5,5,7,2,1,3,4,6).withIndex()){
            val e=HybridFixtures.evidence(category,true);val input=JSONObject().put("id","").put("revision",index+1).put("model_evidence",e).put("attribution",e.getJSONObject("attribution"))
            val facts=TsanetExplanationFacts.from(e)!!
            val start=System.nanoTime();val note=HybridActivityNote.render(facts);val immediateMs=(System.nanoTime()-start)/1e6
            check("Protocol Lab" in note && "This does not confirm an attack" in note)
            val latch=CountDownLatch(1);var result: JSONObject?=null;var error: String?=null
            val tick=SystemClock.elapsedRealtime();val packets=LearnedLive.packets
            test.runOnMainSync{LlamaClient.explain(context,input){value,failure->result=value;error=failure;latch.countDown()}}
            check(latch.await(160,TimeUnit.SECONDS)){"Hybrid worker timed out"};check(error==null && result!=null){error?:"No worker result"}
            val row=result!!;check(row.optString("runtime_error").isEmpty())
            check(row.getString("pipeline_version")==HybridActivityNote.VERSION && row.getBoolean("guidance_only_generation"))
            check(row.getString("display").startsWith(HybridActivityNote.prefix(facts)))
            check("Protocol Lab (nids.protocollab)" in row.getString("display"))
            check(row.getBoolean("warm_model_reused")== (index>0))
            row.put("fixture_class",category).put("note_assembly_ms",immediateMs).put("request_wall_ms",SystemClock.elapsedRealtime()-tick)
                .put("capture_packets_during_request",LearnedLive.packets-packets).put("capture_queue_drops",LearnedLive.queueDrops)
            report.getJSONArray("trials").put(row);File(directory,"runtime.json").writeText(report.toString(2))
        }
        check(LearnedLive.running);report.put("passed",true).put("live_incidents_or_notifications_inserted",false)
        test.runOnMainSync{LlamaClient.releaseIfIdle()};return report
    }
    fun run(options: Bundle){
        val result=Bundle();var code=Activity.RESULT_OK
        try{
            val mode=options.getString("mode")
            val report=if(mode=="hybrid_runtime")runtime() else if(mode=="hybrid_attribution"){
                val resolver=UidResolver(context);resolver.refresh();check(resolver.status.startsWith("connected socket snapshot:")){resolver.status}
                val owner=resolver.lookupFlow(6,options.getString("initiator")!!,options.getString("responder")!!)
                check(owner.optString("status")=="best_effort" && owner.getJSONArray("packages").length()==1){owner.toString()}
                check(owner.getJSONArray("packages").getString(0)=="nids.trafficlab"){owner.toString()}
                val expected=options.getString("match_kind") ?: "connected";check(owner.getString("match_kind")==expected){owner.toString()}
                val e=HybridFixtures.evidence(5,true).put("attribution",owner)
                val note=HybridActivityNote.render(TsanetExplanationFacts.from(e)!!)
                check("NIDS Traffic Lab (nids.trafficlab)" in note)
                if(expected=="listener")check("delivery to that app is not established" in note)
                JSONObject().put("passed",true).put("owner",owner).put("display",note).put("lookup_scope",if(expected=="listener")"Synthetic endpoint lookup against a real owned listening socket; no attack/connection delivery claimed" else "Real benign TCP connection; no attack detection claimed")
            }else HybridNoteContract.run(context)
            File(directory,(mode?.removePrefix("hybrid_") ?: "contracts")+".json").writeText(report.toString(2));result.putString("report",report.toString())
        }catch(e: Throwable){code=Activity.RESULT_CANCELED;result.putString("error",e.stackTraceToString())}
        test.finish(code,result)
    }
}
