package nids.app

import android.content.Context
import nids.core.TsanetSnapshot
import org.json.JSONObject
import org.pytorch.executorch.EValue
import org.pytorch.executorch.Module
import org.pytorch.executorch.Tensor
import java.io.File

class TsanetScorer(context: Context): AutoCloseable{
    val manifest=JSONObject(context.assets.open("tsanet_context_manifest.json").bufferedReader().use{it.readText()})
    private val flowBuffer=Tensor.allocateFloatBuffer(32)
    private val contextBuffer=Tensor.allocateFloatBuffer(78)
    private val inputs=arrayOf(EValue.from(Tensor.fromBlob(flowBuffer,longArrayOf(1,32))),
        EValue.from(Tensor.fromBlob(contextBuffer,longArrayOf(1,78))))
    private val module: Module
    var inferenceNanos=0L;private set
    init{
        val file=File(context.filesDir,"tsanet_context_v1.pte")
        val expected=manifest.getString("model_sha256")
        if(!file.exists() || LearnedShortFlowScorer.sha256(file)!=expected){
            val temporary=File(context.filesDir,"tsanet_context_v1.pte.tmp")
            context.assets.open("tsanet_context.pte").use{input->temporary.outputStream().use{input.copyTo(it)}}
            require(LearnedShortFlowScorer.sha256(temporary)==expected){"Context model checksum failed"}
            check(temporary.renameTo(file)){"Context model installation failed"}
        }
        module=Module.load(file.absolutePath,Module.LOAD_MODE_MMAP,1)
        try{
            module.loadMethod("forward")
            val check=JSONObject(context.assets.open("tsanet_context_selfcheck.json").bufferedReader().use{it.readText()})
            require(check.getString("model_sha256")==expected)
            val cases=check.getJSONArray("cases")
            for(i in 0 until cases.length()){
                val row=cases.getJSONObject(i)
                fun array(name: String)=row.getJSONArray(name).let{a->FloatArray(a.length()){a.getDouble(it).toFloat()}}
                val actual=forward(array("flow"),array("context"));val wanted=array("expected")
                require(actual.indices.all{k->kotlin.math.abs(actual[k]-wanted[k])<check.getDouble("absolute_tolerance")}){"Context numeric self-check failed"}
                require(actual.indices.maxBy{actual[it]}==wanted.indices.maxBy{wanted[it]}){"Context decision self-check failed"}
            }
        }catch(e: Throwable){module.close();throw e}
    }
    fun score(snapshot: TsanetSnapshot)=forward(snapshot.flow,snapshot.context)
    fun forward(flow: FloatArray,context: FloatArray): FloatArray{
        require(flow.size==32 && context.size==78 && flow.all{it.isFinite()} && context.all{it.isFinite()})
        flowBuffer.clear();flowBuffer.put(flow);flowBuffer.rewind()
        contextBuffer.clear();contextBuffer.put(context);contextBuffer.rewind()
        val begin=System.nanoTime()
        val result=module.forward(*inputs)[0].toTensor().dataAsFloatArray
        inferenceNanos+=System.nanoTime()-begin
        require(result.size==7 && result.all{it.isFinite()}){"Invalid model output"}
        return result
    }
    override fun close(){module.close()}
}
