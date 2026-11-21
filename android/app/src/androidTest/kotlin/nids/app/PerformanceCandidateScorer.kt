// Test-only production scorer copy: only manifest/model/fixture loading redirects to an isolated bundle.
package nids.app

import android.content.Context
import nids.core.AlignedSnapshot
import nids.core.AlignedV2Policy
import org.json.JSONObject
import org.pytorch.executorch.EValue
import org.pytorch.executorch.Module
import org.pytorch.executorch.Tensor
import java.io.File
import kotlin.math.abs

/** Attested aligned models, embedded normalization and frozen gate/type cutoffs. */
class PerformanceCandidateScorer(private val context: Context,private val bundle: File): AutoCloseable{
    val gateManifest=json("aligned_v2_gate_manifest.json")
    val diagnosisManifest=json("aligned_v2_diagnosis_manifest.json")
    val policy=AlignedV2Policy(gateManifest.getDouble("gate_threshold"),gateManifest.getDouble("type_score_cutoff"))
    private val flowBuffer=Tensor.allocateFloatBuffer(32)
    private val contextBuffer=Tensor.allocateFloatBuffer(115)
    private val inputs=arrayOf(EValue.from(Tensor.fromBlob(flowBuffer,longArrayOf(1,32))),
        EValue.from(Tensor.fromBlob(contextBuffer,longArrayOf(1,115))))
    private val gate: Module
    private val diagnosis: Module
    var inferenceNanos=0L;private set
    var diagnosisInferences=0L;private set
    init{
        for(m in listOf(gateManifest,diagnosisManifest)){
            require(m.getString("schema")=="phone-aligned-v2" && m.getBoolean("normalization_embedded"))
            require(m.getBoolean("diagnosis_never_vetoes_gate"))
            require(m.getString("feature_contract_sha256")==gateManifest.getString("feature_contract_sha256"))
        }
        val family=gateManifest.optString("model_family","preserved-v2")
        require(family==diagnosisManifest.optString("model_family","preserved-v2"))
        require(gateManifest.getString("job")=="gate_s0")
        when(family){
            "preserved-v2"->require(diagnosisManifest.getString("job")=="diagnosis64_s1")
            "real-phone-augmented-v1"->{
                require(diagnosisManifest.getString("job")=="diagnosis_s1")
                require(gateManifest.getString("checkpoint_variant")=="final")
                require(diagnosisManifest.getString("checkpoint_variant")=="best")
                require(gateManifest.getBoolean("controlled_trial_only") && diagnosisManifest.getBoolean("controlled_trial_only"))
            }
            else->error("Unsupported aligned model family")
        }
        require(gateManifest.getDouble("gate_threshold")==diagnosisManifest.getDouble("gate_threshold"))
        require(gateManifest.getDouble("type_score_cutoff")==diagnosisManifest.getDouble("type_score_cutoff"))
        gate=load("gate",gateManifest)
        try{diagnosis=load("diagnosis",diagnosisManifest)}catch(e: Throwable){gate.close();throw e}
        try{
            gate.loadMethod("forward");diagnosis.loadMethod("forward")
            selfcheck("gate",gate,gateManifest,1);selfcheck("diagnosis",diagnosis,diagnosisManifest,7)
        }catch(e: Throwable){close();throw e}
        inferenceNanos=0;diagnosisInferences=0
    }
    private fun json(name: String): JSONObject{
        require(bundle.canonicalFile.parentFile==File(context.filesDir,"performance_v1/candidates").canonicalFile)
        return JSONObject(File(bundle,name).readText())
    }
    private fun load(kind: String,manifest: JSONObject): Module{
        val file=File(bundle,"aligned_v2_$kind.pte");val expected=manifest.getString("model_sha256")
        require(manifest.optBoolean("performance_only") && file.exists() && LearnedShortFlowScorer.sha256(file)==expected)
        return Module.load(file.absolutePath,Module.LOAD_MODE_MMAP,1)
    }
    private fun selfcheck(kind: String,module: Module,manifest: JSONObject,size: Int){
        val fixture=json("aligned_v2_${kind}_selfcheck.json")
        require(fixture.getString("model_sha256")==manifest.getString("model_sha256"))
        val cases=fixture.getJSONArray("cases")
        for(i in 0 until cases.length()){
            val row=cases.getJSONObject(i)
            fun values(key: String)=row.getJSONArray(key).let{a->FloatArray(a.length()){a.getDouble(it).toFloat()}}
            val actual=forward(module,values("flow"),values("context"),size);val expected=values("expected")
            require(expected.size==size && actual.indices.all{abs(actual[it]-expected[it])<=fixture.getDouble("absolute_tolerance")+abs(expected[it])*.0002}){"v2 $kind numeric self-check failed"}
            if(size==1)require(policy.flagged(policy.probability(actual[0]))==policy.flagged(policy.probability(expected[0])))
            else require(actual.indices.maxBy{actual[it]}==expected.indices.maxBy{expected[it]})
        }
    }
    private fun forward(module: Module,flow: FloatArray,history: FloatArray,size: Int): FloatArray{
        require(flow.size==32 && history.size==115 && flow.all{it.isFinite()} && history.all{it.isFinite()})
        flowBuffer.clear();flowBuffer.put(flow);flowBuffer.rewind()
        contextBuffer.clear();contextBuffer.put(history);contextBuffer.rewind()
        val begin=System.nanoTime();val output=module.forward(*inputs)[0].toTensor().dataAsFloatArray
        inferenceNanos+=System.nanoTime()-begin
        require(output.size==size && output.all{it.isFinite()}){"Invalid v2 model output"}
        return output
    }
    fun score(snapshot: AlignedSnapshot)=score(snapshot.flow.flow,snapshot.context)
    fun score(flow: FloatArray,history: FloatArray): nids.core.AlignedV2Decision{
        val logit=forward(gate,flow,history,1)[0]
        var error=""
        val logits=if(policy.flagged(policy.probability(logit))){
            diagnosisInferences++
            try{forward(diagnosis,flow,history,7)}catch(e: Exception){error=(e.javaClass.simpleName+": "+e.message).take(240);null}
        }else null
        return policy.decide(logit,logits).copy(diagnosisError=error)
    }
    override fun close(){diagnosis.close();gate.close()}
}
