package nids.core

import java.io.File
import kotlin.math.exp

data class AlignedV2Decision(val flagged: Boolean,val classId: Int,val gateScore: Float,
    val diagnosisScores: FloatArray,val diagnosisConfidence: Float,val diagnosisError: String="")

/** Frozen v2: a positive binary decision always remains an alert. */
class AlignedV2Policy(val gateThreshold: Double,val typeCutoff: Double){
    init{require(gateThreshold in 0.0..1.0 && typeCutoff in 0.0..1.0)}
    fun probability(logit: Float): Float{
        require(logit.isFinite())
        return (if(logit>=0)1.0/(1.0+exp(-logit.toDouble())) else exp(logit.toDouble())/(1.0+exp(logit.toDouble()))).toFloat()
    }
    fun flagged(score: Float)=score.toDouble()>=gateThreshold
    fun decide(gateLogit: Float,diagnosisLogits: FloatArray?): AlignedV2Decision{
        val gate=probability(gateLogit)
        if(!flagged(gate))return AlignedV2Decision(false,0,gate,FloatArray(0),0f)
        if(diagnosisLogits==null)return AlignedV2Decision(true,7,gate,FloatArray(0),0f)
        require(diagnosisLogits.size==7 && diagnosisLogits.all{it.isFinite()})
        val maximum=diagnosisLogits.max();val weights=diagnosisLogits.map{exp((it-maximum).toDouble())};val total=weights.sum()
        val scores=FloatArray(7){(weights[it]/total).toFloat()};val best=scores.indices.maxBy{scores[it]}
        val category=if(best!=0 && scores[best].toDouble()>=typeCutoff)best else 7
        return AlignedV2Decision(true,category,gate,scores,scores[best])
    }
}

object AlignedV2PolicyCheck{
    fun run(): Map<String,Any>{
        val policy=AlignedV2Policy(0.7858333333333334,.6)
        check(!policy.decide(-10f,null).flagged)
        check(policy.decide(10f,null).flagged && policy.decide(10f,null).classId==7)
        check(policy.decide(10f,floatArrayOf(10f,0f,0f,0f,0f,0f,0f)).classId==7)
        check(policy.decide(10f,FloatArray(7)).classId==7)
        for(c in 1..6){val logits=FloatArray(7);logits[c]=10f;check(policy.decide(10f,logits).classId==c)}
        check(!policy.flagged(.7858f) && policy.flagged(.7859f))
        var rejected=false;try{policy.decide(Float.NaN,null)}catch(_: IllegalArgumentException){rejected=true};check(rejected)
        return mapOf("passed" to true,"binary_warning_never_vetoed" to true,"unknown_type_retains_alert" to true,"negative_gate_skips_diagnosis" to true)
    }
    @JvmStatic fun main(args: Array<String>){
        val result=run().toMutableMap()
        if(args.isNotEmpty()){
            val policy=AlignedV2Policy(.7858333333333334,.6);var rows=0
            File(args[0]).forEachLine{line->if(line.isNotBlank()){
                val v=line.split('\t');require(v.size==10)
                val actual=policy.decide(v[0].toFloat(),FloatArray(7){v[it+1].toFloat()})
                check(actual.classId==v[8].toInt() && actual.flagged==(v[9]=="1")){"v2 policy mismatch at row $rows"};rows++
            }}
            result["compared_rows"]=rows;result["decision_flips"]=0
        }
        println(AlignedContract.json(result))
    }
}
