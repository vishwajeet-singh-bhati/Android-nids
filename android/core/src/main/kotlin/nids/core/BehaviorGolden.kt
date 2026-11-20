package nids.core

import java.io.File
import kotlin.math.abs

object BehaviorGolden {
    @JvmStatic fun main(args: Array<String>) {
        val directory=File(args.single())
        val expected=File(directory,"expected.tsv").readLines().associate { line -> val p=line.split('\t'); Pair(p[0].toInt(),p[1]) to p }
        val state=BehaviorActivity();var checked=0;var maximum=0.0
        fun verify(index: Int, snapshots: List<BehaviorSnapshot>) {
            for(snapshot in snapshots){
                val gold=expected[Pair(index,snapshot.host)] ?: error("Unexpected behavior snapshot $index")
                check(snapshot.endSecond==gold[2].toLong())
                val wanted=gold[3].split(',').map{it.toFloat()}
                check(wanted.size==snapshot.features.size)
                wanted.indices.forEach { i -> val delta=abs(wanted[i].toDouble()-snapshot.features[i]);maximum=maxOf(maximum,delta);check(delta<1e-6){"Behavior mismatch index=$index feature=$i delta=$delta"} }
                checked++
            }
        }
        val lines=File(directory,"packets.tsv").readLines()
        lines.forEachIndexed { index,line ->
            val c=line.split('\t');val p=ParsedPacket(c[0].toDouble(),c[1].toInt(),c[2],c[3],c[4].toInt(),c[5].toInt(),c[6].toInt(),c[7].toInt(),c[8].toLong(),c[9].toInt(),byteArrayOf())
            verify(index,state.push(p))
        }
        verify(lines.size,state.flush());check(checked==expected.size)
        val bounded=BehaviorActivity(maxHosts=1);val p=ParsedPacket(0.0,6,"a","b",1,2,0,2,0,0,byteArrayOf());bounded.push(p);check(bounded.resets==1L && !bounded.healthy(1) && bounded.healthy(60))
        println("BEHAVIOR_FEATURE_PARITY_PASS snapshots=$checked max_abs_error=$maximum bounded_state_check=pass")
    }
}
