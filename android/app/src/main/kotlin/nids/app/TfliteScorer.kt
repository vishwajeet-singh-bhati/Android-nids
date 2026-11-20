package nids.app

import android.content.Context
import org.tensorflow.lite.Interpreter
import nids.core.PendingWindow
import nids.core.Scorer
import nids.core.WindowTensors
import java.nio.ByteBuffer
import java.nio.ByteOrder

/** Runs one window at a time through the TFLite model in assets/ (e.g. model_int8_wonly.tflite or model_fp32.tflite). */
class TfliteScorer(ctx: Context, assetName: String, threads: Int = 2) : Scorer, AutoCloseable {
    private val interp: Interpreter
    private val slot = IntArray(4) { -1 }   // 0 meta, 1 mask, 2 payload, 3 agg -> interpreter input index
    private val bMeta = buf(12 * 32 * 4)
    private val bMask = buf(32 * 4)
    private val bPay = buf(128 * 32 * 4)
    private val bAgg = buf(22 * 4)

    init {
        val bytes = ctx.assets.open(assetName).use { it.readBytes() }
        val bb = ByteBuffer.allocateDirect(bytes.size).order(ByteOrder.nativeOrder())
        bb.put(bytes); bb.rewind()
        interp = Interpreter(bb, Interpreter.Options().setNumThreads(threads))
        for (i in 0 until interp.inputTensorCount) {
            val n = interp.getInputTensor(i).name()
            when {
                "meta" in n -> slot[0] = i
                "mask" in n -> slot[1] = i
                "payload" in n -> slot[2] = i
                "agg" in n -> slot[3] = i
            }
        }
        require(slot.toSet().size == 4 && slot.all { it >= 0 }) { "could not map the model's inputs by name" }
    }

    private fun validate() {
        val expected = arrayOf(intArrayOf(1,12,32), intArrayOf(1,32), intArrayOf(1,128,32), intArrayOf(1,22))
        for (k in 0..3) {
            val t = interp.getInputTensor(slot[k])
            require(t.shape().contentEquals(expected[k])) { "wrong input shape for slot $k" }
            require(t.dataType().toString() == if (k == 2) "INT32" else "FLOAT32") { "wrong input type" }
        }
        require(interp.getOutputTensor(0).shape().contentEquals(intArrayOf(1))) { "wrong output shape" }
    }

    private fun buf(n: Int) = ByteBuffer.allocateDirect(n).order(ByteOrder.nativeOrder())

    private fun fill(b: ByteBuffer, f: FloatArray) { b.rewind(); b.asFloatBuffer().put(f); b.rewind() }

    fun run(t: WindowTensors): Double {
        validate()
        fill(bMeta, t.meta); fill(bMask, t.mask); fill(bAgg, t.agg)
        bPay.rewind(); bPay.asIntBuffer().put(t.payload); bPay.rewind()
        val inputs = arrayOfNulls<Any>(4)
        inputs[slot[0]] = bMeta; inputs[slot[1]] = bMask; inputs[slot[2]] = bPay; inputs[slot[3]] = bAgg
        val out = FloatArray(1)
        @Suppress("UNCHECKED_CAST")
        interp.runForMultipleInputsOutputs(inputs as Array<Any>, mapOf(0 to out))
        require(out[0].isFinite()) { "non-finite TFLite result" }
        return out[0].toDouble()
    }

    override fun score(items: List<PendingWindow>) = DoubleArray(items.size) { run(items[it].tensors) }
    override fun close() = interp.close()
}
