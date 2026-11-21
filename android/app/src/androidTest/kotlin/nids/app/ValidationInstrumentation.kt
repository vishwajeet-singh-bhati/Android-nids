package nids.app

import android.app.Activity
import android.app.Instrumentation
import android.os.Bundle
import org.json.JSONObject
import java.io.File

class ValidationInstrumentation: Instrumentation() {
    private var options=Bundle()
    override fun onCreate(arguments: Bundle?) { options=arguments ?: Bundle(); start() }
    override fun onStart() {
        if(options.getString("mode") in setOf("hybrid_contract","hybrid_runtime","hybrid_attribution")){
            HybridPipelineValidation(this,targetContext).run(options);return
        }
        if(options.getString("mode")=="performance"){
            PerformanceBench(this,targetContext).run(options)
            return
        }
        if(options.getString("mode")=="aligned_v2_native"){
            val result=Bundle()
            try{
                val features=nids.core.AlignedCheck.run();val policy=nids.core.AlignedV2PolicyCheck.run()
                val delivery=nids.core.CaptureDeliveryClockCheck.run()
                AlignedV2Scorer(targetContext).use{scorer->
                    fun fixture(kind: String)=JSONObject(targetContext.assets.open("aligned_v2_${kind}_selfcheck.json").bufferedReader().use{it.readText()}).getJSONArray("cases")
                    val gates=fixture("gate");val diagnosis=fixture("diagnosis");check(gates.length()==diagnosis.length())
                    for(i in 0 until gates.length()){
                        val g=gates.getJSONObject(i);val d=diagnosis.getJSONObject(i)
                        fun values(row: JSONObject,name: String)=row.getJSONArray(name).let{a->FloatArray(a.length()){a.getDouble(it).toFloat()}}
                        check(values(g,"flow").contentEquals(values(d,"flow")) && values(g,"context").contentEquals(values(d,"context")))
                        val expected=scorer.policy.decide(values(g,"expected")[0],values(d,"expected"))
                        val actual=scorer.score(values(g,"flow"),values(g,"context"))
                        check(actual.classId==expected.classId && actual.flagged==expected.flagged)
                    }
                    val unknown=JSONObject().put("schema","tsanet_phone_evidence_v1").put("feature_schema","phone-aligned-v2")
                        .put("class_id",7).put("binary_flag",true).put("attribution",JSONObject().put("status","unknown"))
                        .put("flow_packets",12).put("flow_duration_seconds",1.0)
                    val facts=TsanetExplanationFacts.from(unknown)!!
                    check(facts.optString("suspected_pattern")=="Unclassified")
                    check(TsanetExplanationFacts.fallback(facts).contains("undetermined"))
                    val report=JSONObject().put("passed",true).put("schema","phone-aligned-v2")
                        .put("gate_model_sha256",scorer.gateManifest.getString("model_sha256"))
                        .put("diagnosis_model_sha256",scorer.diagnosisManifest.getString("model_sha256"))
                        .put("contract_sha256",scorer.gateManifest.getString("feature_contract_sha256"))
                        .put("feature_checks",JSONObject(features)).put("policy_checks",JSONObject(policy))
                        .put("delivery_clock_checks",JSONObject(delivery))
                        .put("selfcheck_rows",gates.length()).put("pipeline_decision_flips",0)
                        .put("device",android.os.Build.MODEL).put("attack_detection_test",false)
                    options.getString("input")?.let{name->
                        require(name.matches(Regex("[A-Za-z0-9_.-]+")))
                        report.put("replay",JSONObject(nids.core.AlignedReplay.run(File(targetContext.filesDir,name),File(targetContext.filesDir,"aligned_v2_replay.tsv"))))
                    }
                    File(targetContext.filesDir,"aligned_v2_native_validation.json").writeText(report.toString(2))
                    result.putString("report",report.toString())
                }
                finish(Activity.RESULT_OK,result)
            }catch(e: Throwable){result.putString("error",e.toString());finish(Activity.RESULT_CANCELED,result)}
            return
        }
        if(options.getString("mode")=="tsanet_start"){
            targetContext.getSharedPreferences("background_monitor",android.content.Context.MODE_PRIVATE).edit()
                .putBoolean("validation_trace",options.getString("trace")=="true").apply()
            runOnMainSync{targetContext.startForegroundService(android.content.Intent(targetContext,TsanetCaptureService::class.java))}
            val end=android.os.SystemClock.elapsedRealtime()+30000
            while(LearnedLive.status!="Monitoring" && android.os.SystemClock.elapsedRealtime()<end)Thread.sleep(250)
            val result=Bundle();result.putString("report",LearnedLive.status)
            finish(if(LearnedLive.status=="Monitoring")Activity.RESULT_OK else Activity.RESULT_CANCELED,result);return
        }
        if(options.getString("mode")=="tsanet_native"){
            val result=Bundle()
            try{
                nids.core.TsanetCheck.main(emptyArray())
                val freshOwner=JSONObject().put("status","best_effort").put("uid",123)
                check(TsanetExplanationFacts.ownerSnapshot(freshOwner,JSONObject().put("status","unknown")).getInt("uid")==123)
                val ambiguous=JSONObject().put("status","unknown").put("reason","Ambiguous socket ownership")
                check(TsanetExplanationFacts.ownerSnapshot(ambiguous,freshOwner).optString("status")=="unknown")
                TsanetScorer(targetContext).use{scorer->
                    val report=JSONObject().put("passed",true).put("model_sha256",scorer.manifest.getString("model_sha256"))
                        .put("device",android.os.Build.MODEL).put("android",android.os.Build.VERSION.RELEASE)
                        .put("feature_checks",true).put("native_selfchecks",true)
                    File(targetContext.filesDir,"tsanet_native_validation.json").writeText(report.toString(2))
                    result.putString("report",report.toString())
                }
                finish(Activity.RESULT_OK,result)
            }catch(e: Throwable){result.putString("error",e.toString());finish(Activity.RESULT_CANCELED,result)}
            return
        }
        if(options.getString("mode")=="tsanet_pipeline"){
            val result=Bundle();var outcome=Activity.RESULT_OK
            val report=JSONObject().put("synthetic_evidence",true).put("attack_detection_test",false)
            var id=""
            fun await(seconds: Int,condition: ()->Boolean){val end=android.os.SystemClock.elapsedRealtime()+seconds*1000L;while(!condition()){check(android.os.SystemClock.elapsedRealtime()<end){"Context pipeline check timed out"};Thread.sleep(500)}}
            try{
                runOnMainSync{targetContext.startForegroundService(android.content.Intent(targetContext,TsanetCaptureService::class.java))}
                await(30){LearnedLive.running && LearnedLive.status=="Monitoring"}
                val owner=JSONObject().put("status","unknown").put("direction","unknown").put("app_label","Validation fixture: app unknown")
                val evidence=JSONObject().put("schema","tsanet_phone_evidence_v1").put("class_id",5).put("suspected_pattern","Port Scan")
                    .put("fingerprint","validation-context-"+java.util.UUID.randomUUID()).put("test_only",true)
                    .put("attribution",owner).put("flow_packets",12).put("flow_duration_seconds",1.0)
                    .put("sampled_prior_connections_5m",10).put("sampled_target_ports_5m",8)
                    .put("history_complete",false).put("capture_healthy",true)
                val facts=TsanetExplanationFacts.from(evidence)!!
                check(TsanetExplanationFacts.from(evidence.put("class_id",0))==null);evidence.put("class_id",5)
                check(!TsanetExplanationFacts.draftConsistent("App com.invented.bad sent 999 packets",facts))
                val row=ObservationStore.record(targetContext,"tsanet_pattern",1,evidence);id=row.getString("id")
                val packets=LearnedLive.packets
                runOnMainSync{ObservationNotifications.show(targetContext,row);AutomaticExplanations.pump(targetContext)}
                await(180){ObservationStore.get(targetContext,id)?.optString("explanation_status")=="complete"}
                val completed=ObservationStore.get(targetContext,id)!!
                val explanation=completed.getJSONObject("explanation")
                check(explanation.optString("runtime_error").isEmpty() && explanation.optString("raw_local_draft").isNotEmpty())
                check(explanation.optString("display").contains("does not confirm",true) || explanation.optString("display").contains("not confirmed",true))
                val notification=targetContext.getSystemService(android.app.NotificationManager::class.java).activeNotifications.any{it.id==id.hashCode()}
                check(notification){"Activity notification was not posted"}
                check(LearnedLive.running && LearnedLive.status=="Monitoring")
                report.put("passed",true).put("explanation",explanation).put("notification_posted",notification)
                    .put("capture_running",LearnedLive.running).put("packets_during_explanation",LearnedLive.packets-packets)
                    .put("queue_drops",LearnedLive.queueDrops)
                result.putString("report",report.toString())
            }catch(e: Throwable){outcome=Activity.RESULT_CANCELED;report.put("passed",false).put("error",e.toString());result.putString("error",report.toString())}
            finally{
                File(targetContext.filesDir,"tsanet_pipeline_validation.json").writeText(report.toString(2))
                if(id.isNotEmpty()){
                    targetContext.getSystemService(android.app.NotificationManager::class.java).cancel(id.hashCode())
                    ObservationStore.close(targetContext)
                    android.database.sqlite.SQLiteDatabase.openDatabase(File(targetContext.filesDir,"activity_history_v1.db").absolutePath,null,android.database.sqlite.SQLiteDatabase.OPEN_READWRITE).use{database->
                        database.delete("observations","id=? AND fingerprint LIKE 'validation-context-%'",arrayOf(id))
                    }
                }
            }
            finish(outcome,result);return
        }
        if(options.getString("mode")=="validation_cleanup"){
            val result=Bundle()
            try{
                ObservationStore.close(targetContext)
                var removed=0
                android.database.sqlite.SQLiteDatabase.openDatabase(File(targetContext.filesDir,"activity_history_v1.db").absolutePath,null,android.database.sqlite.SQLiteDatabase.OPEN_READWRITE).use{database ->
                    val ids=ArrayList<String>()
                    database.rawQuery("SELECT id FROM observations WHERE json_extract(body,'$.model_evidence.test_only')=1 AND fingerprint LIKE 'validation-%'",null).use{while(it.moveToNext())ids.add(it.getString(0))}
                    database.beginTransaction()
                    try{for(id in ids){database.delete("feedback","json_extract(body,'$.observation_id')=?",arrayOf(id));removed+=database.delete("observations","id=?",arrayOf(id))};database.setTransactionSuccessful()}finally{database.endTransaction()}
                }
                for(directory in targetContext.filesDir.listFiles().orEmpty().filter{it.isDirectory && it.name.startsWith("mentor-validation-")}){
                    check(directory.canonicalFile.parentFile==targetContext.filesDir.canonicalFile)
                    val sandbox=object: android.content.ContextWrapper(targetContext){override fun getFilesDir()=directory}
                    ObservationStore.close(sandbox)
                    for(file in directory.listFiles().orEmpty()){check(file.isFile);check(file.delete())}
                    check(directory.delete())
                }
                result.putString("report","VALIDATION_CLEANUP_PASS removed_synthetic_rows=$removed");finish(Activity.RESULT_OK,result)
            }catch(e: Exception){result.putString("error",e.toString());finish(Activity.RESULT_CANCELED,result)}
            return
        }
        if(options.getString("mode")=="mentor_store"){
            val result=Bundle();var outcome=Activity.RESULT_OK
            val directory=File(targetContext.filesDir,"mentor-validation-"+java.util.UUID.randomUUID()).apply{mkdirs()}
            val sandbox=object: android.content.ContextWrapper(targetContext){override fun getFilesDir()=directory}
            try{
                val first=ObservationStore.record(sandbox,"connection_pattern",2,JSONObject().put("test_only",true))
                ObservationStore.feedback(sandbox,first.getString("id"),1,"expected","validation sandbox")
                val changed=ObservationStore.record(sandbox,"connection_pattern",1,JSONObject().put("test_only",true))
                check(changed.getInt("count")==3 && changed.getInt("revision")==2)
                check(changed.getJSONObject("feedback").getInt("revision")==1)
                var rejected=false
                try{ObservationStore.feedback(sandbox,first.getString("id"),1,"expected","")}catch(_: IllegalArgumentException){rejected=true}
                check(rejected)
                val exported=java.io.ByteArrayOutputStream()
                ObservationStore.export(sandbox,exported,JSONObject().put("test_only",true))
                val history=JSONObject(exported.toString("UTF-8")).getJSONArray("feedback").getJSONObject(0)
                check(!history.getBoolean("verified_ground_truth") && history.getJSONObject("evidence_snapshot").getInt("revision")==1)
                check(ObservationStore.count(sandbox,"dismissed")==1L)
                check(ObservationStore.nextQueued(sandbox)==null)
                ObservationStore.feedback(sandbox,first.getString("id"),2,"unsure","")
                check(ObservationStore.nextQueued(sandbox)?.getString("id")==first.getString("id"))
                ObservationStore.explanationState(sandbox,first.getString("id"),"running")
                ObservationStore.close(sandbox)
                ObservationStore.recoverQueue(sandbox)
                check(ObservationStore.get(sandbox,first.getString("id"))!!.getString("explanation_status")=="queued")
                for(i in 0 until 105)ObservationStore.record(sandbox,"connection_pattern",1,JSONObject().put("fingerprint","page-$i"))
                check(ObservationStore.count(sandbox)==106L)
                val ids=HashSet<String>()
                for(offset in listOf(0,50,100))for(row in ObservationStore.list(sandbox,50,"all",offset))check(ids.add(row.getString("id")))
                check(ids.size==106)
                val complete=java.io.ByteArrayOutputStream()
                ObservationStore.export(sandbox,complete,JSONObject().put("schema",2))
                check(JSONObject(complete.toString("UTF-8")).getJSONArray("observations").length()==106)
                ObservationStore.close(sandbox)
                android.database.sqlite.SQLiteDatabase.openDatabase(File(directory,"activity_history_v1.db").absolutePath,null,android.database.sqlite.SQLiteDatabase.OPEN_READWRITE).use{database ->
                    val expired=(System.currentTimeMillis()-8L*24*60*60*1000).toString()
                    database.execSQL("UPDATE observations SET time_ms=? WHERE id=?",arrayOf(expired,first.getString("id")))
                    database.execSQL("UPDATE feedback SET time_ms=?",arrayOf(expired))
                }
                check(ObservationStore.get(sandbox,first.getString("id"))==null)
                check(ObservationStore.count(sandbox)==105L)
                val retained=java.io.ByteArrayOutputStream()
                ObservationStore.export(sandbox,retained,JSONObject())
                check(JSONObject(retained.toString("UTF-8")).getJSONArray("feedback").length()==0)
                val inbox=PatternInbox(sandbox);inbox.shortFlow(4.0,2.0,2)
                check(inbox.flush(null,false).isEmpty())
                result.putString("report","MENTOR_STORE_PASS grouping versioned_feedback stale_review_rejected quality_abstention no_automatic_training retention pagination export dismissal persistent_queue")

            }catch(e: Exception){result.putString("error",e.toString());outcome=Activity.RESULT_CANCELED}
            finally{ObservationStore.close(sandbox);directory.listFiles()?.forEach{it.delete()};directory.delete()}
            finish(outcome,result)
            return
        }
        if(options.getString("mode")=="attribution_runtime"){
            val result=Bundle()
            try{
                val resolver=UidResolver(targetContext);resolver.refresh()
                check(resolver.status.startsWith("connected socket snapshot:")){resolver.status}
                val owner=resolver.lookupFlow(6,options.getString("initiator")!!,options.getString("responder")!!)
                check(owner.getInt("uid")==options.getString("expected_uid")!!.toInt()){owner.toString()}
                check(owner.getString("direction")=="incoming"){owner.toString()}
                check(owner.getString("ownership_note").contains("not identified as the attacker"))
                val unknown=resolver.lookupFlow(6,"192.0.2.1:1","192.0.2.2:2")
                check(unknown.getString("status")=="unknown" && unknown.getString("direction")=="unknown")
                result.putString("report",JSONObject().put("passed",true).put("real_socket",owner).put("unknown",unknown).toString());finish(Activity.RESULT_OK,result)
            }catch(e: Exception){result.putString("error",e.toString());finish(Activity.RESULT_CANCELED,result)}
            return
        }
        if(options.getString("mode")=="automatic_runtime"){
            val result=Bundle();var outcome=Activity.RESULT_OK;val ids=ArrayList<String>();val report=JSONObject().put("synthetic_evidence",true)
            fun await(seconds: Int,condition: ()->Boolean){val end=android.os.SystemClock.elapsedRealtime()+seconds*1000L;while(!condition()){check(android.os.SystemClock.elapsedRealtime()<end){"Runtime validation timed out"};Thread.sleep(500)}}
            fun activity(label: String): JSONObject {
                val row=ObservationStore.record(targetContext,"connection_pattern",1,JSONObject().put("fingerprint","validation-"+java.util.UUID.randomUUID()).put("test_only",true).put("attribution",JSONObject().put("status","unknown").put("direction","unknown").put("app_label","Validation fixture: app unknown")))
                ids.add(row.getString("id"));runOnMainSync{AutomaticExplanations.pump(targetContext)};return row
            }
            try{
                runOnMainSync{targetContext.startForegroundService(android.content.Intent(targetContext,ShortFlowCaptureService::class.java))}
                await(30){LearnedLive.status=="Monitoring"}
                val packets=LearnedLive.packets;val checks=LearnedLive.inferences
                val cold=activity("cold");val coldId=cold.getString("id")
                await(180){ObservationStore.get(targetContext,coldId)?.optString("explanation_status")=="complete"}
                val coldReport=ObservationStore.get(targetContext,coldId)!!.getJSONObject("explanation")
                check(coldReport.optString("runtime_error").isEmpty() && coldReport.optString("raw_local_draft").isNotEmpty())
                val warm=activity("warm");val warmId=warm.getString("id")
                await(90){ObservationStore.get(targetContext,warmId)?.optString("explanation_status")=="complete"}
                val warmReport=ObservationStore.get(targetContext,warmId)!!.getJSONObject("explanation")
                check(warmReport.getBoolean("warm_model_reused") && warmReport.getLong("load_ms")==0L)
                check(warmReport.getInt("worker_pid")==coldReport.getInt("worker_pid"))
                check(warmReport.optString("runtime_error").isEmpty() && warmReport.optString("raw_local_draft").isNotEmpty())
                report.put("cold",coldReport).put("warm",warmReport)
                report.put("packets_during_explanations",LearnedLive.packets-packets).put("checks_during_explanations",LearnedLive.inferences-checks).put("capture_queue_drops",LearnedLive.queueDrops)
                check(LearnedLive.running && LearnedLive.packets>packets && LearnedLive.inferences>checks)
                await(140){!LlamaLive.workerResident}
                report.put("idle_eviction",true)
                val cancelled=activity("cancel");val cancelId=cancelled.getString("id")
                await(15){LlamaLive.running && LlamaLive.observationId==cancelId}
                runOnMainSync{val row=ObservationStore.get(targetContext,cancelId)!!;ObservationStore.feedback(targetContext,cancelId,row.getInt("revision"),"expected","synthetic cancellation validation");AutomaticExplanations.dismiss(targetContext,cancelId)}
                await(10){!LlamaLive.running && !LlamaLive.workerResident}
                check(ObservationStore.get(targetContext,cancelId)!!.getString("disposition")=="dismissed")
                report.put("dismissal_cancellation",true).put("passed",true)
                File(targetContext.filesDir,"automatic_runtime_validation.json").writeText(report.toString(2))
                result.putString("report",report.toString());
            }catch(e: Exception){report.put("passed",false).put("error",e.toString());File(targetContext.filesDir,"automatic_runtime_validation.json").writeText(report.toString(2));result.putString("error",report.toString());outcome=Activity.RESULT_CANCELED}
            finally{
                runOnMainSync{LlamaClient.cancel("Validation cleanup")}
                for(id in ids)targetContext.getSystemService(android.app.NotificationManager::class.java).cancel(id.hashCode())
                ObservationStore.close(targetContext)
                android.database.sqlite.SQLiteDatabase.openDatabase(File(targetContext.filesDir,"activity_history_v1.db").absolutePath,null,android.database.sqlite.SQLiteDatabase.OPEN_READWRITE).use{database ->
                    for(id in ids){database.delete("observations","id=?",arrayOf(id));database.delete("feedback","json_extract(body,'$.observation_id')=?",arrayOf(id))}
                }
            }
            finish(outcome,result)
            return
        }
        if(options.getString("mode")=="local_explain") {
            val result=Bundle()
            try {
                val line=File(targetContext.filesDir,"learned_network.jsonl").readLines().asReversed().first { JSONObject(it).optString("event")=="network_anomaly" }
                val report=LocalExplainer(targetContext).explain(JSONObject(line))
                report.put("device",android.os.Build.MODEL).put("android",android.os.Build.VERSION.RELEASE).put("test_input","latest actual recorded unconfirmed warning").put("runtime_pass",report.optString("raw_local_draft").isNotEmpty() && report.optString("runtime_error").isEmpty())
                File(targetContext.filesDir,"last_local_explanation.json").writeText(report.toString(2));result.putString("report",report.toString());finish(Activity.RESULT_OK,result)
            }catch(e: Exception){result.putString("error",e.toString());finish(Activity.RESULT_CANCELED,result)}
            return
        }
        val model=options.getString("model") ?: "model_fp32.tflite"
        val result=Bundle()
        try {
            val session=SessionLog(targetContext,model)
            val report=SelfTest.run(targetContext,model)
            val j=session.context(JSONObject().put("passed",true).put("report",report))
            File(targetContext.filesDir,"validation.json").writeText(j.toString())
            result.putString("report",report)
            finish(Activity.RESULT_OK,result)
        } catch(e: Exception) {
            val j=JSONObject().put("passed",false).put("error",e.toString()).put("model",model)
            File(targetContext.filesDir,"validation.json").writeText(j.toString())
            result.putString("error",e.toString()); finish(Activity.RESULT_CANCELED,result)
        }
    }
}
