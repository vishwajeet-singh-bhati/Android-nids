package nids.core

import java.io.File
import java.util.ArrayDeque
import kotlin.math.abs

object CascadeGolden {
    @JvmStatic fun main(args: Array<String>){
        var activity=CascadeActivity();val ready=ArrayDeque<CascadeSnapshot>();var compared=0;var maximum=0.0
        val raw=ByteArray(40);raw[0]=0x45;raw[3]=40;raw[9]=6;raw[32]=0x50
        raw[24]=0x12;raw[25]=0x34;raw[26]=0x56;raw[27]=0x78
        raw[28]=0xfe.toByte();raw[29]=0xdc.toByte();raw[30]=0xba.toByte();raw[31]=0x98.toByte()
        val parsed=PacketParser.decode(raw,PacketParser.DLT_RAW,100.0,0,emptySet())!!
        check(parsed.seq==0x12345678L && parsed.ack==0xfedcba98L){"Unsigned TCP sequence/ACK parsing failed"}
        fun compare(actual: FloatArray,values: String){
            val expected=values.split(',').map{it.toFloat()};check(actual.size==expected.size)
            for(i in actual.indices){val error=abs(actual[i]-expected[i]).toDouble();maximum=maxOf(maximum,error)
                check(error<0.00001){"Cascade feature mismatch at $compared index $i: ${actual[i]} versus ${expected[i]}"}}
        }
        File(args[0]).forEachLine{line->
            val s=line.split('\t')
            when(s[0]){
                "R"->{check(ready.isEmpty());activity=CascadeActivity()}
                "P"->{val proto=s[2].toInt();ready.addAll(activity.push(ParsedPacket(s[1].toDouble(),proto,s[3],s[4],s[5].toInt(),s[6].toInt(),
                    if(proto==6)PROTO_TCP else PROTO_UDP,s[7].toInt(),s[8].toLong(),s[10].toInt(),byteArrayOf(),s[9].toLong())))}
                "F"->ready.addAll(activity.flush())
                "E"->{check(ready.isNotEmpty());val snapshot=ready.removeFirst()
                    check(snapshot.host==s[1] && snapshot.endSecond==s[2].toLong())
                    compare(snapshot.features,s[3]);compare(snapshot.sequence,s[4]);compare(snapshot.mask,s[5])
                    check(snapshot.healthy==(s[6]=="1"));compared++}
                else->error("Unknown fixture operation")
            }
        }
        check(ready.isEmpty() && compared>0)
        if(args.size>1){val out=File(args[1]);out.parentFile.mkdirs()
            out.writeText("{\"passed\":true,\"snapshots\":$compared,\"maximum_absolute_feature_error\":$maximum,\"unsigned_tcp_ack\":true}\n")}
        println("CASCADE_FEATURE_PARITY_PASS snapshots=$compared maximum_error=$maximum unsigned_tcp_ack=true")
    }
}
