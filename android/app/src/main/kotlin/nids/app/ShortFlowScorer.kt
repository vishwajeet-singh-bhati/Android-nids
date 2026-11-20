package nids.app

import android.content.Context
import nids.core.ShortFlowScorer
import nids.core.ShortFlowTensors
import org.json.JSONObject
import org.pytorch.executorch.Module
import org.pytorch.executorch.Tensor
import org.pytorch.executorch.EValue
import java.io.File
import java.security.MessageDigest

class LearnedShortFlowScorer(context: Context, trace: File?=null) : ShortFlowScorer, AutoCloseable {
    val manifest=JSONObject(context.assets.open("shortflow_manifest.json").bufferedReader().use { it.readText() })
    val threshold=manifest.getDouble("threshold_logit")
    private val traceWriter=trace?.bufferedWriter()
    private var traced=0
    private val packetBuffer=Tensor.allocateFloatBuffer(72)
    private val maskBuffer=Tensor.allocateFloatBuffer(8)
    private val contextBuffer=Tensor.allocateFloatBuffer(16)
    private val inputs=arrayOf(EValue.from(Tensor.fromBlob(packetBuffer,longArrayOf(1,8,9))),EValue.from(Tensor.fromBlob(maskBuffer,longArrayOf(1,8))),EValue.from(Tensor.fromBlob(contextBuffer,longArrayOf(1,16))))
    var lastPositiveFeatures: String?=null; private set
    private val module: Module
    init {
        val file=File(context.filesDir,"shortflow_model.pte")
        val wanted=manifest.getString("model_sha256")
        if(!file.exists() || sha256(file)!=wanted) context.assets.open("shortflow_model.pte").use { input -> file.outputStream().use { input.copyTo(it) } }
        require(sha256(file)==wanted) { "Short-flow model integrity check failed" }
        module=Module.load(file.absolutePath,Module.LOAD_MODE_MMAP,1)
        module.loadMethod("forward")
        try {
            val check=JSONObject(context.assets.open("shortflow_selfcheck.json").bufferedReader().use{it.readText()})
            require(check.getString("model_sha256")==wanted)
            val cases=check.getJSONArray("cases")
            for(i in 0 until cases.length()){
                val c=cases.getJSONObject(i)
                fun values(name: String)=c.getJSONArray(name).let{a -> FloatArray(a.length()){a.getDouble(it).toFloat()}}
                val actual=forward(ShortFlowTensors(values("x"),values("mask"),values("context")))
                require(kotlin.math.abs(actual-c.getDouble("expected_logit"))<check.getDouble("absolute_tolerance")){"Short-flow numeric self-check failed"}
            }
        }catch(e: Throwable){module.close();traceWriter?.close();throw e}
    }
    override fun score(t: ShortFlowTensors): Double {
        val result=forward(t)
        lastPositiveFeatures=if(result>=threshold)JSONObject().put("feature_version","shortflow_8x9_context16").put("model_sha256",manifest.getString("model_sha256")).put("packets",org.json.JSONArray(t.packets.toList())).put("mask",org.json.JSONArray(t.mask.toList())).put("context",org.json.JSONArray(t.context.toList())).put("model_logit",result).toString() else null
        if(traceWriter!=null && traced++<10000){
            val row=JSONObject().put("x",org.json.JSONArray(t.packets.toList())).put("mask",org.json.JSONArray(t.mask.toList())).put("context",org.json.JSONArray(t.context.toList())).put("logit",result)
            traceWriter.write(row.toString());traceWriter.newLine()
        }
        return result
    }
    private fun forward(t: ShortFlowTensors): Double {
        packetBuffer.clear();packetBuffer.put(t.packets);packetBuffer.rewind()
        maskBuffer.clear();maskBuffer.put(t.mask);maskBuffer.rewind()
        contextBuffer.clear();contextBuffer.put(t.context);contextBuffer.rewind()
        return module.forward(*inputs)[0].toTensor().dataAsFloatArray[0].toDouble().also{require(it.isFinite())}
    }
    override fun close(){try{module.close()}finally{traceWriter?.close()}}
    companion object {
        fun sha256(file: File): String {
            val digest=MessageDigest.getInstance("SHA-256")
            file.inputStream().use { input -> val b=ByteArray(65536); while(true){val n=input.read(b);if(n<0)break;digest.update(b,0,n)} }
            return digest.digest().joinToString("") { "%02x".format(it.toInt() and 255) }
        }
    }
}
