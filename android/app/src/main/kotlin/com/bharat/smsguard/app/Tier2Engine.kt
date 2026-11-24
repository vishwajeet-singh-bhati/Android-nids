package com.bharat.smsguard.app

import android.content.Context
import com.bharat.smsguard.tier1.BertTokenizer
import org.pytorch.executorch.EValue
import org.pytorch.executorch.Module
import org.pytorch.executorch.Tensor
import java.io.File
import kotlin.math.exp

/** Serialized local inference: the exported Module owns reusable output buffers. */
class Tier2Engine(context: Context) {
    private val tokenizer = BertTokenizer(nids.app.SafetyAssets.install(context, "sms/vocab.txt",
        org.json.JSONObject(context.assets.open("sms/manifest.json").bufferedReader().use { it.readText() }).getString("vocab.txt")).readLines())
    private val modelFile = nids.app.SafetyAssets.install(context, "sms/ptq_int8_b1.pte",
        org.json.JSONObject(context.assets.open("sms/manifest.json").bufferedReader().use { it.readText() }).getString("ptq_int8_b1.pte"))
    private val module = Module.load(modelFile.absolutePath, Module.LOAD_MODE_MMAP, 1)
    @Synchronized
    fun logits(modelText: String): FloatArray {
        val input = tokenizer.encode(modelText)
        val shape = longArrayOf(1, 128)
        val result = module.forward(
            EValue.from(Tensor.fromBlob(input.ids, shape)),
            EValue.from(Tensor.fromBlob(input.mask, shape)),
            EValue.from(Tensor.fromBlob(input.types, shape)),
        )[0].toTensor().dataAsFloatArray.copyOf()
        check(result.size == 3 && result.all { it.isFinite() }) { "Invalid Tier-2 output" }
        return result
    }
    fun scores(modelText: String): Map<String, Double> {
        val z = logits(modelText)
        val max = z.max()
        val exps = z.map { exp((it - max).toDouble()) }
        val total = exps.sum()
        return listOf("ham", "spam", "smishing").mapIndexed { i, label -> label to exps[i] / total }.toMap()
    }
}
