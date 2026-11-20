package nids.core

import java.io.File

/** Deterministic runtime checks, independent of the neural-network weights. */
object RuntimeRegression {
    @JvmStatic fun main(args: Array<String>) {
        val c=RuntimeConfig.parse(File(args[0]).readText()+"\ncontinuous=1\n")
        val burst=BurstDetector(30.0,2)
        check(!burst.add(100.0) && !burst.add(200.0) && !burst.add(100.0))
        check(burst.add(201.0))
        for(z in listOf(Double.NaN,Double.POSITIVE_INFINITY,Double.NEGATIVE_INFINITY)) {
            check(runCatching { Policy.step(PolicyState(),z,PolicyParams(0.0,0.5,2,3.0)) }.isFailure)
        }
        val starts=ArrayList<Int>()
        val e=StreamEngine(c, { items -> starts.addAll(items.map { it.key.start }); DoubleArray(items.size) { -10.0 } },1)
        for(i in 0 until 2000) e.feed(ParsedPacket(100.0+i*0.01,6,"10.0.0.2","8.8.8.8",40000,443,PROTO_TCP,if(i==0) TCP_SYN else TCP_ACK,100L+i*50,50,ByteArray(50)))
        e.finish()
        check(starts.max()>1500) { "long-flow scoring stopped" }
        val idle=StreamEngine(c,{ items -> DoubleArray(items.size) { 10.0 } },1)
        for(i in 0..4) idle.feed(ParsedPacket(100.0+i*0.01,6,"10.0.0.2","8.8.8.8",40000,443,PROTO_TCP,if(i==0) TCP_SYN else TCP_ACK,100L+i*50,50,ByteArray(50)))
        val alarms=idle.tick(300.0)
        check(alarms.size==1 && alarms[0].ts==300.0 && idle.activeFlows==0)
        println("RUNTIME REGRESSIONS PASS")
    }
}
