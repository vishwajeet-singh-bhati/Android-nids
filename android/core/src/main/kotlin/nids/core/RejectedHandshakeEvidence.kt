package nids.core

import kotlin.math.expm1

/** Recognize limited rejected-handshake evidence; never suppress a model decision.
 * Applies only to incoming, rejected TCP handshakes with no application bytes.
 * A sweep, concentrated volume or unhealthy capture defeats
 * this description. No address, port or application identity is exempted.
 */
object RejectedHandshakeEvidence {
    const val VERSION="rejected-handshake-v1"
    fun matches(flow: FloatArray, context: FloatArray, incoming: Boolean,
             captureHealthy: Boolean, classId: Int): Boolean {
        require(flow.size==32 && context.size==115)
        if(flow.any{!it.isFinite()} || context.any{!it.isFinite()})return false
        if(!incoming || !captureHealthy || classId !in setOf(1,7))return false
        if(flow[1]!=1f || flow[2]!=1f || flow[3]!=0f || flow[4]!=0f ||
           flow[28]!=0f || flow[29]!=1f || flow[30]!=1f || flow[31]!=1f)return false
        fun count(i: Int)=kotlin.math.round(expm1(context[i].toDouble())).toInt().coerceAtLeast(0)
        if(listOf(6,38,70).any{count(it)>=3})return false
        if(count(0)>=15 || count(32)>=31 || count(21)>=7)return false
        return true
    }
}

/** Edge cases protect scan/flood detection and prevent blanket control filtering. */
object RejectedHandshakeEvidenceCheck {
    @JvmStatic fun main(args: Array<String>){
        fun flow()=FloatArray(32).apply{this[1]=1f;this[2]=1f;this[29]=1f;this[30]=1f;this[31]=1f}
        fun context()=FloatArray(115).apply{this[114]=kotlin.math.ln(301.0).toFloat()}
        fun test(f: FloatArray=flow(),c: FloatArray=context(),incoming: Boolean=true,
                 healthy: Boolean=true,category: Int=1)=
            RejectedHandshakeEvidence.matches(f,c,incoming,healthy,category)
        check(test());check(test(category=7))
        for(category in listOf(0,2,3,4,5,6))check(!test(category=category))
        check(!test(incoming=false));check(!test(healthy=false))
        check(!test(f=flow().apply{this[3]=1f}));check(!test(f=flow().apply{this[4]=1f}))
        check(!test(f=flow().apply{this[29]=0f}));check(!test(f=flow().apply{this[30]=0f}))
        check(!test(f=flow().apply{this[28]=1f}));check(!test(f=flow().apply{this[1]=2f}))
        check(!test(f=flow().apply{this[0]=Float.NaN}))
        for(i in listOf(6,38,70)){
            check(test(c=context().apply{this[i]=kotlin.math.ln(3.0).toFloat()}))
            check(!test(c=context().apply{this[i]=kotlin.math.ln(4.0).toFloat()}))
        }
        for((i,n) in listOf(0 to 15,32 to 31,21 to 7)){
            check(test(c=context().apply{this[i]=kotlin.math.ln(n.toDouble()).toFloat()}))
            check(!test(c=context().apply{this[i]=kotlin.math.ln(n+1.0).toFloat()}))
        }
        println("{\"passed\":true,\"policy\":\"${RejectedHandshakeEvidence.VERSION}\",\"scope\":\"Evidence recognition boundary checks; no detection suppressed\"}")
    }
}
