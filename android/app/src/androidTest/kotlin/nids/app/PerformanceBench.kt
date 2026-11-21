package nids.app

import android.app.Activity
import android.app.Instrumentation
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.os.*
import org.json.JSONArray
import org.json.JSONObject
import org.pytorch.executorch.EValue
import org.pytorch.executorch.Module
import org.pytorch.executorch.Tensor
import java.io.File
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import kotlin.math.abs

/** Private numeric fixtures only; no attack traffic or incident/notification insertion. */
class PerformanceBench(private val test: Instrumentation,private val context: Context){
    private lateinit var directory: File
    private lateinit var report: JSONObject
    private val trials=JSONArray()
    private data class Frame(val flow: FloatArray,val history: FloatArray,val gate: FloatArray,val diagnosis: FloatArray)
    private fun array(row: JSONObject,name: String)=row.getJSONArray(name).let{v->FloatArray(v.length()){v.getDouble(it).toFloat()}}
    private fun frames(): List<Frame>{
        fun load(kind: String)=JSONObject(context.assets.open("aligned_v2_${kind}_selfcheck.json").bufferedReader().use{it.readText()}).getJSONArray("cases")
        val gate=load("gate");val diagnosis=load("diagnosis");check(gate.length()==diagnosis.length())
        return (0 until gate.length()).map{i->
            val g=gate.getJSONObject(i);val d=diagnosis.getJSONObject(i)
            check(array(g,"flow").contentEquals(array(d,"flow")) && array(g,"context").contentEquals(array(d,"context")))
            Frame(array(g,"flow"),array(g,"context"),array(g,"expected"),array(d,"expected"))
        }
    }
    private fun save(){File(directory,"report.json").writeText(report.toString(2))}
    private fun phase(name: String){
        val row=JSONObject().put("phase",name).put("pid",Process.myPid()).put("time_ms",System.currentTimeMillis()).put("elapsed_ms",SystemClock.elapsedRealtime())
        File(directory,"phase.json").writeText(row.toString());test.sendStatus(0,Bundle().apply{putString("phase",name)})
    }
    private fun memory(): JSONObject{
        val m=Debug.MemoryInfo();Debug.getMemoryInfo(m)
        val r=Runtime.getRuntime();val battery=context.registerReceiver(null,IntentFilter(Intent.ACTION_BATTERY_CHANGED))
        return JSONObject().put("pss_kib",m.totalPss).put("private_dirty_kib",m.totalPrivateDirty)
            .put("native_heap_allocated_bytes",Debug.getNativeHeapAllocatedSize()).put("java_heap_used_bytes",r.totalMemory()-r.freeMemory())
            .put("cpu_ms",Process.getElapsedCpuTime()).put("thermal_status",context.getSystemService(PowerManager::class.java).currentThermalStatus)
            .put("battery_temperature_c",(battery?.getIntExtra(BatteryManager.EXTRA_TEMPERATURE,0)?:0)/10.0)
            .put("battery_percent",battery?.getIntExtra(BatteryManager.EXTRA_LEVEL,-1)).put("memory_stats",JSONObject(m.memoryStats))
    }
    private fun timings(name: String,values: List<Double>,cpu: Long,wall: Double): JSONObject{
        val sorted=values.sorted();fun p(q: Double)=sorted[((sorted.size-1)*q).toInt()]
        return JSONObject().put("name",name).put("iterations",values.size).put("median_ms",p(.5)).put("p95_ms",p(.95))
            .put("p99_ms",p(.99)).put("min_ms",sorted.first()).put("max_ms",sorted.last()).put("mean_ms",values.average())
            .put("timed_wall_ms",wall).put("process_cpu_ms",cpu).put("process_cpu_one_core_percent",100*cpu/wall)
            .put("process_cpu_all_cores_percent",100*cpu/wall/Runtime.getRuntime().availableProcessors()).put("after",memory())
    }
    private fun startMonitor(){
        test.runOnMainSync{context.startForegroundService(Intent(context,TsanetCaptureService::class.java))}
        val end=SystemClock.elapsedRealtime()+40000
        while(!LearnedLive.running || LearnedLive.status!="Monitoring"){
            check(SystemClock.elapsedRealtime()<end){"Monitor failed to initialize"};Thread.sleep(200)
        }
    }
    private fun detector(){
        val cases=frames();phase("current_scorer_cold_load");val t=System.nanoTime()
        AlignedV2Scorer(context).use{scorer->
            val load=(System.nanoTime()-t)/1e6;report.put("current_scorer_load_selfcheck_ms",load)
            val expected=cases.map{scorer.policy.decide(it.gate[0],it.diagnosis)}
            repeat(3){cases.forEach{scorer.score(it.flow,it.history)}}
            phase("current_exact_cascade");val before=memory();val cpu=Process.getElapsedCpuTime();val begin=System.nanoTime()
            val times=ArrayList<Double>();val quiet=ArrayList<Double>();val flagged=ArrayList<Double>();var errors=0
            repeat(80){for((i,row) in cases.withIndex()){
                val tick=System.nanoTime();val actual=scorer.score(row.flow,row.history);val elapsed=(System.nanoTime()-tick)/1e6
                times.add(elapsed);(if(actual.flagged)flagged else quiet).add(elapsed)
                if(actual.classId!=expected[i].classId || actual.flagged!=expected[i].flagged)errors++
            }}
            val result=timings("current_exact_cascade",times,Process.getElapsedCpuTime()-cpu,(System.nanoTime()-begin)/1e6)
                .put("before",before).put("decision_flips",errors).put("gate_only_samples",quiet.size).put("gate_and_diagnosis_samples",flagged.size)
                .put("gate_only_median_ms",if(quiet.isEmpty())JSONObject.NULL else quiet.sorted()[quiet.size/2])
                .put("gate_and_diagnosis_median_ms",if(flagged.isEmpty())JSONObject.NULL else flagged.sorted()[flagged.size/2])
            check(errors==0);trials.put(result);save()
        }
        for(threads in listOf(1,2,4))for(kind in listOf("gate","diagnosis")){
            val name="current_${kind}_threads_$threads";phase(name)
            val path=File(context.filesDir,"aligned_v2_$kind.pte");val loadStart=System.nanoTime()
            Module.load(path.absolutePath,Module.LOAD_MODE_MMAP,threads).use{module->
                module.loadMethod("forward");val loadMs=(System.nanoTime()-loadStart)/1e6
                val f=Tensor.allocateFloatBuffer(32);val h=Tensor.allocateFloatBuffer(115)
                val inputs=arrayOf(EValue.from(Tensor.fromBlob(f,longArrayOf(1,32))),EValue.from(Tensor.fromBlob(h,longArrayOf(1,115))))
                var maximum=0.0
                fun forward(row: Frame): Double{
                    f.clear();f.put(row.flow);f.rewind();h.clear();h.put(row.history);h.rewind()
                    val start=System.nanoTime();val output=module.forward(*inputs)[0].toTensor().dataAsFloatArray;val elapsed=(System.nanoTime()-start)/1e6
                    val wanted=if(kind=="gate")row.gate else row.diagnosis
                    check(output.size==wanted.size && output.all{it.isFinite()})
                    for(i in output.indices){val error=abs(output[i]-wanted[i]).toDouble();maximum=maxOf(maximum,error);check(error<=.002+abs(wanted[i])*.0002)}
                    return elapsed
                }
                repeat(3){cases.forEach{forward(it)}}
                val before=memory();val cpu=Process.getElapsedCpuTime();val begin=System.nanoTime();val times=ArrayList<Double>()
                repeat(80){cases.forEach{times.add(forward(it))}}
                trials.put(timings(name,times,Process.getElapsedCpuTime()-cpu,(System.nanoTime()-begin)/1e6)
                    .put("requested_threads",threads).put("load_and_method_ms",loadMs).put("maximum_logit_error",maximum).put("before",before));save()
            }
        }
    }
    private fun detectorCandidate(variant: String){
        require(variant in setOf("hoisted_fp32","e8_blockmax_reconstructed","e8_rowsigma_reconstructed"))
        val bundle=File(context.filesDir,"performance_v1/candidates/$variant")
        fun fixture(kind: String)=JSONObject(File(bundle,"aligned_v2_${kind}_selfcheck.json").readText()).getJSONArray("cases")
        val gates=fixture("gate");val diagnoses=fixture("diagnosis")
        val cases=(0 until gates.length()).map{i->val g=gates.getJSONObject(i);val d=diagnoses.getJSONObject(i);Frame(array(g,"flow"),array(g,"context"),array(g,"expected"),array(d,"expected"))}
        phase("${variant}_scorer_load");val loadStart=System.nanoTime()
        PerformanceCandidateScorer(context,bundle).use{scorer->
            val loadMs=(System.nanoTime()-loadStart)/1e6
            val wanted=cases.map{scorer.policy.decide(it.gate[0],it.diagnosis)}
            repeat(3){cases.forEach{scorer.score(it.flow,it.history)}}
            phase("${variant}_cascade");val cpu=Process.getElapsedCpuTime();val began=System.nanoTime();val times=ArrayList<Double>();var errors=0
            repeat(80){cases.forEachIndexed{i,row->
                val tick=System.nanoTime();val actual=scorer.score(row.flow,row.history);times.add((System.nanoTime()-tick)/1e6)
                if(actual.flagged!=wanted[i].flagged || actual.classId!=wanted[i].classId)errors++
            }}
            check(errors==0);trials.put(timings("${variant}_cascade",times,Process.getElapsedCpuTime()-cpu,(System.nanoTime()-began)/1e6)
                .put("load_selfcheck_ms",loadMs).put("parity_flips_vs_candidate_reference",errors));save()
        }
        for(kind in listOf("gate","diagnosis")){
            phase("${variant}_${kind}_threads_1")
            Module.load(File(bundle,"aligned_v2_$kind.pte").absolutePath,Module.LOAD_MODE_MMAP,1).use{module->
                module.loadMethod("forward")
                val f=Tensor.allocateFloatBuffer(32);val h=Tensor.allocateFloatBuffer(115)
                val inputs=arrayOf(EValue.from(Tensor.fromBlob(f,longArrayOf(1,32))),EValue.from(Tensor.fromBlob(h,longArrayOf(1,115))))
                fun forward(row: Frame): Double{
                    f.clear();f.put(row.flow);f.rewind();h.clear();h.put(row.history);h.rewind()
                    val tick=System.nanoTime();val output=module.forward(*inputs)[0].toTensor().dataAsFloatArray;val ms=(System.nanoTime()-tick)/1e6
                    val expected=if(kind=="gate")row.gate else row.diagnosis
                    check(output.size==expected.size && output.indices.all{abs(output[it]-expected[it])<=.002+abs(expected[it])*.0002})
                    return ms
                }
                repeat(3){cases.forEach{forward(it)}}
                val cpu=Process.getElapsedCpuTime();val start=System.nanoTime();val times=ArrayList<Double>()
                repeat(80){cases.forEach{times.add(forward(it))}}
                trials.put(timings("${variant}_${kind}_threads_1",times,Process.getElapsedCpuTime()-cpu,(System.nanoTime()-start)/1e6));save()
            }
        }
    }
    private fun detectorPair(){
        val cases=frames()
        AlignedV2Scorer(context).use{baseline->
            PerformanceCandidateScorer(context,File(context.filesDir,"performance_v1/candidates/hoisted_fp32")).use{candidate->
                val expected=cases.map{baseline.policy.decide(it.gate[0],it.diagnosis)}
                val scorers=listOf<Pair<String,(Frame)->nids.core.AlignedV2Decision>>(
                    "current" to {r->baseline.score(r.flow,r.history)},"hoisted_fp32" to {r->candidate.score(r.flow,r.history)})
                repeat(3){scorers.forEach{(_,score)->cases.forEach{score(it)}}}
                for(round in 0 until 3){
                    val order=if(round%2==0)scorers else scorers.reversed()
                    for((variant,score) in order){
                        val name="paired_${variant}_${round+1}";phase(name)
                        val cpu=Process.getElapsedCpuTime();val start=System.nanoTime();val values=ArrayList<Double>();var flips=0
                        repeat(80){cases.forEachIndexed{i,row->
                            val tick=System.nanoTime();val actual=score(row);values.add((System.nanoTime()-tick)/1e6)
                            if(actual.classId!=expected[i].classId || actual.flagged!=expected[i].flagged)flips++
                        }}
                        check(flips==0)
                        trials.put(timings(name,values,Process.getElapsedCpuTime()-cpu,(System.nanoTime()-start)/1e6)
                            .put("variant",variant).put("round",round+1).put("decision_flips",flips)
                            .put("scope","Paired one-thread cascade on identical 21 fixtures; both models resident for timing control."));save()
                    }
                }
            }
        }
    }
    private fun explanationFixture(classId: Int,knownReceiver: Boolean=false): JSONObject{
        val owner=if(knownReceiver)JSONObject().put("status","best_effort").put("direction","incoming").put("packages",JSONArray().put("nids.protocollab"))
            else JSONObject().put("status","unknown").put("direction","unknown")
        val evidence=JSONObject().put("schema","tsanet_phone_evidence_v1").put("feature_schema","phone-aligned-v2")
            .put("class_id",classId).put("binary_flag",true).put("attribution",owner).put("flow_packets",if(knownReceiver)37 else 12)
            .put("flow_duration_seconds",1.0).put("prior_connections_5m",10).put("target_ports_5m",8)
            .put("history_complete",!knownReceiver).put("capture_healthy",!knownReceiver).put("test_only",true)
        return JSONObject().put("id","").put("revision",1).put("model_evidence",evidence).put("attribution",owner).put("performance_fixture",true)
    }
    private fun llama(profile: String){
        phase("monitoring_only_idle");startMonitor();Thread.sleep(10000)
        // Use the actual app IPC worker, checksum path, prompts and acceptance
        // policy. No fabricated incident is inserted in history or notified.
        for((round,classId) in listOf(5,7,2).withIndex()){
            test.runOnMainSync{LlamaClient.releaseIfIdle()};Thread.sleep(1500)
            for(warm in listOf(false,true)){
                val name="${profile}_llama_${if(warm)"warm" else "cold"}_${round+1}";phase(name)
                val input=explanationFixture(classId);val done=CountDownLatch(1);var result: JSONObject?=null;var failure: String?=null
                val before=memory();val start=System.nanoTime();val cpu=Process.getElapsedCpuTime()
                check(profile=="current");test.runOnMainSync{LlamaClient.explain(context,input){report,error->result=report;failure=error;done.countDown()}}
                check(done.await(160,TimeUnit.SECONDS)){"Llama request watchdog expired"}
                check(failure==null && result!=null){failure?:"No explanation"}
                val row=result!!;check(row.optString("runtime_error").isEmpty() && row.optString("raw_local_draft").isNotEmpty())
                check(row.getBoolean("warm_model_reused")==warm){"Requested cold/warm state did not match"}
                row.put("name",name).put("expected_warm",warm).put("fixture_class",classId)
                    .put("before_main_process",before).put("after_main_process",memory())
                    .put("request_wall_ms",(System.nanoTime()-start)/1e6).put("main_process_cpu_ms",Process.getElapsedCpuTime()-cpu)
                    .put("monitor_packets",LearnedLive.packets).put("monitor_inferences",LearnedLive.inferences).put("monitor_queue_drops",LearnedLive.queueDrops)
                trials.put(row);save()
            }
        }
        test.runOnMainSync{LlamaClient.releaseIfIdle()};Thread.sleep(1500)
    }
    private fun llamaCompare(candidateProfile: String){
        require(candidateProfile in setOf("concise_prefix96","structured_tail48","guidance_only48"))
        phase("component_idle_monitor_paused")
        test.runOnMainSync{context.stopService(Intent(context,TsanetCaptureService::class.java))}
        val end=SystemClock.elapsedRealtime()+30000
        while(LearnedLive.running){check(SystemClock.elapsedRealtime()<end);Thread.sleep(100)}
        // Module.load configures the process-wide ExecuTorch CPU pool. Match
        // the isolated production Llama worker's four-thread execution. Do not
        // start the detector here: its initialization requests one thread.
        Module.load(File(context.filesDir,"aligned_v2_gate.pte").absolutePath,Module.LOAD_MODE_MMAP,4).use{it.loadMethod("forward")}
        report.put("component_cpu_pool_requested_threads",4).put("monitor_active_during_component_ab",false)
        Thread.sleep(3000)
        for((round,classId) in listOf(5,7,2).withIndex()){
            val order=if(round%2==0)listOf("current",candidateProfile) else listOf(candidateProfile,"current")
            for(profile in order){
                PerformanceLocalExplainer.releaseModel()
                for(warm in listOf(false,true)){
                    val name="direct_${profile}_${if(warm)"warm" else "cold"}_${round+1}";phase(name)
                    val before=memory();val cpu=Process.getElapsedCpuTime();val start=System.nanoTime()
                    val row=PerformanceLocalExplainer(context).explain(explanationFixture(classId),profile)
                    check(row.optString("runtime_error").isEmpty() && row.optString("raw_local_draft").isNotEmpty())
                    check(row.getBoolean("warm_model_reused")==warm)
                    row.put("name",name).put("expected_warm",warm).put("fixture_class",classId)
                        .put("scope","Matched direct component A/B in instrumentation target process; excludes production IPC.")
                        .put("before_process",before).put("after_process",memory()).put("process_cpu_ms",Process.getElapsedCpuTime()-cpu)
                        .put("request_wall_ms",(System.nanoTime()-start)/1e6).put("monitor_queue_drops",LearnedLive.queueDrops)
                    trials.put(row);save()
                }
                PerformanceLocalExplainer.releaseModel()
            }
        }
        if(candidateProfile in setOf("structured_tail48","guidance_only48")){
            for(classId in listOf(1,3,4,6,5)){
                phase("structured_quality_$classId")
                val row=PerformanceLocalExplainer(context).explain(explanationFixture(classId,knownReceiver=classId==5),candidateProfile)
                row.put("name","structured_quality_$classId").put("quality_only",true).put("fixture_class",classId).put("known_receiver",classId==5)
                trials.put(row);save()
            }
            PerformanceLocalExplainer.releaseModel()
        }
    }
    private fun explanationOptions(){
        phase("options_component_monitor_paused")
        test.runOnMainSync{context.stopService(Intent(context,TsanetCaptureService::class.java))}
        val end=SystemClock.elapsedRealtime()+30000
        while(LearnedLive.running){check(SystemClock.elapsedRealtime()<end);Thread.sleep(100)}
        Module.load(File(context.filesDir,"aligned_v2_gate.pte").absolutePath,Module.LOAD_MODE_MMAP,4).use{it.loadMethod("forward")}
        report.put("component_cpu_pool_requested_threads",4).put("monitor_active_during_component_ab",false)
        val fixtures=(1..7).map{explanationFixture(it)}+explanationFixture(5,true)
        val facts=fixtures.map{TsanetExplanationFacts.from(it.getJSONObject("model_evidence"))!!}
        val notes=JSONArray()
        for(fact in facts){
            val text=PerformancePlainNote.render(fact)
            check(TsanetExplanationFacts.draftConsistent(text,fact) && "This does not confirm an attack." in text)
            check(text.contains("${fact.getInt("flow_packets")} network packets"))
            if(!fact.optBoolean("history_complete"))check("history is incomplete" in text)
            if(!fact.optBoolean("capture_complete"))check("traffic was missed" in text)
            notes.put(JSONObject().put("facts",fact).put("display",text).put("words",text.split(Regex("\\s+")).size))
        }
        phase("plain_evidence_renderer");val values=ArrayList<Double>();val cpu=Process.getElapsedCpuTime();val started=System.nanoTime()
        repeat(2000){facts.forEach{val tick=System.nanoTime();PerformancePlainNote.render(it);values.add((System.nanoTime()-tick)/1e6)}}
        trials.put(timings("plain_evidence_renderer",values,Process.getElapsedCpuTime()-cpu,(System.nanoTime()-started)/1e6)
            .put("examples",notes).put("quality_cases",notes.length()).put("uses_language_model",false));save()
        for(profile in listOf("plain_hybrid48","small_full96","small_hybrid48")){
            try{
                for((round,classId) in listOf(5,7,2).withIndex()){
                    PerformanceLocalExplainer.releaseModel()
                    for(warm in listOf(false,true)){
                        phase("${profile}_${if(warm)"warm" else "cold"}_${round+1}")
                        val before=memory();val cpuStart=Process.getElapsedCpuTime()
                        val row=PerformanceLocalExplainer(context).explain(explanationFixture(classId),profile)
                        check(row.getBoolean("warm_model_reused")==warm)
                        row.put("name","${profile}_${if(warm)"warm" else "cold"}_${round+1}").put("fixture_class",classId)
                            .put("process_cpu_ms",Process.getElapsedCpuTime()-cpuStart).put("before_process",before).put("after_process",memory())
                        trials.put(row);save()
                    }
                }
                for(classId in listOf(1,3,4,6,5)){
                    phase("${profile}_quality_$classId")
                    val row=PerformanceLocalExplainer(context).explain(explanationFixture(classId,classId==5),profile)
                    row.put("name","${profile}_quality_$classId").put("quality_only",true).put("fixture_class",classId).put("known_receiver",classId==5)
                    trials.put(row);save()
                }
            }catch(e: Throwable){
                trials.put(JSONObject().put("name","${profile}_runtime_failure").put("runtime_error",e.stackTraceToString()).put("compatible",false));save()
            }finally{PerformanceLocalExplainer.releaseModel()}
        }
    }
    private fun bootWarmupCompare(){
        phase("warmup_component_monitor_paused")
        test.runOnMainSync{context.stopService(Intent(context,TsanetCaptureService::class.java))}
        val deadline=SystemClock.elapsedRealtime()+30000
        while(LearnedLive.running){check(SystemClock.elapsedRealtime()<deadline);Thread.sleep(100)}
        Module.load(File(context.filesDir,"aligned_v2_gate.pte").absolutePath,Module.LOAD_MODE_MMAP,4).use{it.loadMethod("forward")}
        report.put("scope","Matched component A/B, four requested threads, capture paused; boot time counted separately and in total.")
        for((round,category) in listOf(5,7,2).withIndex()){
            val pair=ArrayList<JSONObject>()
            for(prewarm in if(round%2==0)listOf(false,true) else listOf(true,false)){
                PerformanceLocalExplainer.releaseModel();val start=SystemClock.elapsedRealtime()
                phase("boot_warmup_${round}_${if(prewarm)"prepared" else "cold"}")
                val boot=if(prewarm)PerformanceLocalExplainer.bootWarmup(context) else JSONObject().put("boot_total_ms",0)
                val row=PerformanceLocalExplainer(context).explain(explanationFixture(category),"plain_hybrid48")
                check(row.getBoolean("warm_model_reused")==prewarm && row.getBoolean("generated_text_accepted"))
                row.put("name","boot_warmup_${round}_${if(prewarm)"prepared" else "cold"}").put("prewarmed",prewarm)
                    .put("fixture_class",category).put("boot",boot).put("boot_plus_request_ms",SystemClock.elapsedRealtime()-start)
                trials.put(row);pair.add(row);save()
            }
            check(pair[0].getString("normalized_local_draft")==pair[1].getString("normalized_local_draft")){"Prewarm changed the same-input guidance"}
        }
        report.put("same_input_guidance_matches",3).put("warmup_content_leaked",false)
        PerformanceLocalExplainer.releaseModel()
    }
    private fun nativeTokenBudget(){
        phase("native_token_budget_monitor_paused")
        test.runOnMainSync{context.stopService(Intent(context,TsanetCaptureService::class.java))}
        val end=SystemClock.elapsedRealtime()+30000
        while(LearnedLive.running){check(SystemClock.elapsedRealtime()<end);Thread.sleep(100)}
        Module.load(File(context.filesDir,"aligned_v2_gate.pte").absolutePath,Module.LOAD_MODE_MMAP,4).use{it.loadMethod("forward")}
        val baseline=PerformanceLocalExplainer(context).explain(explanationFixture(5),"plain_hybrid48")
        check(baseline.getBoolean("generated_text_accepted"));baseline.put("name","before_truncated_generation");trials.put(baseline);save()
        report.put("token_budget_checks",PerformanceLocalExplainer.nativeBudgetProbes(context))
        val row=PerformanceLocalExplainer(context).explain(explanationFixture(5),"plain_hybrid48")
        row.put("name","after_truncated_generation");trials.put(row);save()
        check(row.getBoolean("generated_text_accepted") && row.getString("normalized_local_draft")==baseline.getString("normalized_local_draft"))
        report.put("guidance_fresh_after_truncated_generation",true);PerformanceLocalExplainer.releaseModel()
    }
    fun run(options: Bundle){
        val result=Bundle();var outcome=Activity.RESULT_OK
        try{
            val session=options.getString("session")?:"baseline";require(session.matches(Regex("[A-Za-z0-9_-]{1,80}")))
            directory=File(context.filesDir,"performance_v1/$session").apply{mkdirs()}
            report=JSONObject().put("session",session).put("device",Build.MODEL).put("android",Build.VERSION.RELEASE)
                .put("runtime","ExecuTorch Android 1.5.1").put("online_cpu_count",Runtime.getRuntime().availableProcessors())
                .put("time_ms",System.currentTimeMillis()).put("trials",trials).put("synthetic_evidence_only",true)
                .put("incident_rows_or_notifications_inserted",false).put("detection_accuracy_test",false).put("before",memory())
            save();when(options.getString("suite")?:"detector"){
                "detector"->detector()
                "llama"->llama(options.getString("profile")?:"current")
                "llama_compare"->llamaCompare(options.getString("profile")?:"concise_prefix96")
                "detector_candidate"->detectorCandidate(options.getString("variant")?:"hoisted_fp32")
                "detector_pair"->detectorPair()
                "explanation_options"->explanationOptions()
                "llama_boot_warmup"->bootWarmupCompare()
                "llama_token_budget"->nativeTokenBudget()
                else->error("Unknown performance suite")
            }
            report.put("passed",true);result.putString("report",report.toString())
        }catch(e: Throwable){outcome=Activity.RESULT_CANCELED;if(::report.isInitialized)report.put("passed",false).put("error",e.stackTraceToString());result.putString("error",e.toString())}
        finally{
            try{PerformanceLocalExplainer.releaseModel()}catch(_: Throwable){}
            if(::report.isInitialized){report.put("after",memory());save();phase("finished")}
            // Instrumentation may restart the app process; restore monitoring.
            try{startMonitor()}catch(_: Throwable){}
        }
        test.finish(outcome,result)
    }
}
