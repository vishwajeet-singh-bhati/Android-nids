package nids.dataset

import java.io.File
import nids.core.*

/** Standalone adapter compiled against the frozen v2 extractor, not a feature change. */
object DatasetReplay{
    @JvmStatic fun main(args: Array<String>){
        require(args.size in 3..4){"capture watched-addresses.txt output.jsonl [native-first-observed-time]"}
        val cutoff=if(args.size==4)args[3].toDouble() else Double.NEGATIVE_INFINITY
        val watched=File(args[1]).readLines().filter{it.isNotBlank()}.toSet()
        val collector=AlignedTsanetCollector(watched);val stats=ParseStats();var frames=0L;var skipped=0L;var last=0.0;var count=0L
        File(args[2]).bufferedWriter().use{writer->
            fun emit(rows: List<AlignedSnapshot>){for(row in rows){val f=row.flow
                writer.write(AlignedContract.json(mapOf("decision_time" to row.decisionTime,"watched" to row.watched,
                    "key" to f.key,"source" to f.source,"destination" to f.destination,"sport" to f.sourcePort,"dport" to f.destinationPort,
                    "protocol" to f.protocol,"start" to f.start,"end" to f.end,"flow" to f.flow.toList(),"context" to row.context.toList()))+"\n");count++
            }}
            File(args[0]).inputStream().buffered(65536).use{stream->val input=CaptureFileStream(stream)
                while(true){val frame=input.next() ?: break;frames++
                    if(frame.ts<cutoff){skipped++;continue};last=maxOf(last,frame.ts)
                    AlignedPacketParser.decode(frame,stats)?.let{emit(collector.feed(it))}}
            }
            emit(collector.advance(last+31,true))
        }
        println(AlignedContract.json(mapOf("frames" to frames,"rows" to count,"parsed" to stats.parsed,"malformed" to stats.malformed,
            "skipped_before_native_capture" to skipped,"native_first_observed_time" to cutoff,
            "late" to collector.late,"forced_reorder" to collector.forcedReorder,"flow_evictions" to collector.flowEvictions,
            "history_evictions" to collector.historyEvictions,"invalid_flows" to collector.invalidFlows)))
    }
}
