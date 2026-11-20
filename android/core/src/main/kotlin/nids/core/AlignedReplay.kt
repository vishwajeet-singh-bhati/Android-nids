package nids.core

import java.io.File

object AlignedReplay{
    fun run(input: File,output: File): Map<String,Any>{
        val collector=AlignedTsanetCollector();val stats=ParseStats();var frames=0L;var rows=0L;var last=0.0
        output.bufferedWriter().use{writer->
            fun emit(values: List<AlignedSnapshot>){for(v in values){
                writer.write(v.decisionTime.toString()+"\t"+v.watched+"\t"+v.flow.key+"\t"+v.flow.flow.joinToString(",")+"\t"+v.context.joinToString(",")+"\n");rows++
            }}
            input.inputStream().use{stream->val reader=CaptureFileStream(stream);while(true){val frame=reader.next() ?: break;frames++;last=maxOf(last,frame.ts)
                AlignedPacketParser.decode(frame,stats)?.let{emit(collector.feed(it))}
            }}
            emit(collector.advance(last+31,true))
        }
        return mapOf("frames" to frames,"rows" to rows,"parsed" to stats.parsed,"malformed" to stats.malformed,
            "late" to collector.late,"forced" to collector.forcedReorder,"flow_evictions" to collector.flowEvictions,
            "history_evictions" to collector.historyEvictions,"invalid" to collector.invalidFlows)
    }
    @JvmStatic fun main(args: Array<String>){require(args.size==2);println(AlignedContract.json(run(File(args[0]),File(args[1]))))}
}
