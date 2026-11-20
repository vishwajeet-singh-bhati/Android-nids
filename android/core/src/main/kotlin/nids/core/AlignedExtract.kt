package nids.core

import java.io.*

/** Offline-only entry point. Shared parser/collector have no label awareness. */
object AlignedExtract{
    private data class Label(val lower: Double,val upper: Double,val target: Int,val fine: Int)
    private class Labels(file: File){
        val map=HashMap<String,MutableList<Label>>()
        init{file.forEachLine{line->if(line.isNotBlank()){val c=line.split('\t');map.getOrPut(c[0]){ArrayList()}.add(Label(c[1].toDouble(),c[2].toDouble(),c[3].toInt(),c[4].toInt()))}}
            for(rows in map.values)rows.sortBy{it.lower}}
        fun match(s: TsanetSnapshot): Pair<Int,Int>{
            val rows=map[s.key] ?: return Pair(-1,-1)
            var label=-2;var fine=-2
            for(r in rows){if(r.lower>s.start+.001)break
                if(r.upper+.001<s.end)continue
                if(label!=-2 && label!=r.target)return Pair(-1,-1)
                label=r.target;fine=if(fine==-2 || fine==r.fine)r.fine else -1
            }
            return if(label==-2)Pair(-1,-1) else Pair(label,fine)
        }
    }
    private fun hash(value: String): Long{var n=-3750763034362895579L;for(b in value.toByteArray()){n=n xor (b.toLong() and 255);n*=1099511628211L};return n}
    @JvmStatic fun main(args: Array<String>){
        if(args.singleOrNull()=="spec"){println(AlignedContract.json(AlignedContract.specification()));return}
        require(args.size in 4..5){"capture labels.tsv|- output-prefix source [packet-limit]"}
        val inputs=if(args[0].startsWith("@"))File(args[0].drop(1)).readLines().filter{it.isNotBlank()}.map{val c=it.split('\t');Pair(File(c[0]),c[1])} else listOf(Pair(File(args[0]),args[3]))
        val labels=if(args[1]=="-")null else Labels(File(args[1]));val prefix=File(args[2]);prefix.parentFile.mkdirs()
        val limit=if(args.size==5)args[4].toLong() else 0L
        var collector=AlignedTsanetCollector();val stats=ParseStats();val classes=LongArray(7);var currentTag=args[3]
        var sourceLate=0L;var sourceForced=0L;var sourceEvictions=0L;var sourceHistoryEvictions=0L;var sourceInvalid=0L
        var records=0L;var written=0L;var unknown=0L;var last=0.0;val begin=System.currentTimeMillis()
        val partial=File(prefix.path+".partial");val buffer=BufferedOutputStream(FileOutputStream(partial),1 shl 20);val writer=DataOutputStream(buffer)
        writer.writeInt(0x4e494432);writer.writeInt(32);writer.writeInt(AlignedContract.CONTEXT);writer.writeLong(0)
        fun emit(rows: List<AlignedSnapshot>){for(row in rows){
            val s=row.flow;val (target,fine)=labels?.match(s) ?: Pair(0,0)
            if(target !in 0..6){unknown++;continue}
            val group=if(currentTag.startsWith("PARROT:") || currentTag.startsWith("AAGM:"))currentTag else currentTag+"|"+s.key
            writer.writeLong(hash(group));writer.writeLong(hash(row.watched));writer.writeDouble(s.start);writer.writeDouble(s.end)
            writer.writeInt(target);writer.writeInt(fine);writer.writeInt(if(row.watched==s.source)0 else 1)
            require(s.flow.size==32 && row.context.size==AlignedContract.CONTEXT)
            for(v in s.flow){require(v.isFinite());writer.writeFloat(v)};for(v in row.context){require(v.isFinite());writer.writeFloat(v)}
            written++;classes[target]++
        }}
        for((input,tag) in inputs){
        collector=AlignedTsanetCollector();currentTag=tag;last=0.0
        input.inputStream().buffered(1 shl 20).use{stream->
            val reader=CaptureFileStream(stream)
            while(true){val frame=reader.next() ?: break;records++;last=maxOf(last,frame.ts)
                AlignedPacketParser.decode(frame,stats)?.let{emit(collector.feed(it))}
                if(records%250000L==0L){val status=mapOf("phase" to "extracting","source" to args[3],"records" to records,"rows" to written,"class_counts" to classes.toList(),"seconds" to (System.currentTimeMillis()-begin)/1000)
                    File(prefix.path+".status.json").writeText(AlignedContract.json(status));println(AlignedContract.json(status))}
                if(limit>0 && records>=limit)break
            }
        }
        emit(collector.advance(last+31,true))
        sourceLate+=collector.late;sourceForced+=collector.forcedReorder;sourceEvictions+=collector.flowEvictions
        sourceHistoryEvictions+=collector.historyEvictions;sourceInvalid+=collector.invalidFlows
        if(limit>0 && records>=limit)break
        }
        writer.flush();writer.close()
        RandomAccessFile(partial,"rw").use{it.seek(12);it.writeLong(written)}
        val output=File(prefix.path+".bin");check(partial.renameTo(output))
        val result=mapOf("state" to "complete","version" to AlignedContract.VERSION,"source" to args[3],"records" to records,"rows" to written,
            "class_counts" to classes.toList(),"unknown_views_excluded" to unknown,"malformed" to stats.malformed,"parsed" to stats.parsed,
            "late" to sourceLate,"forced_reorder" to sourceForced,"flow_evictions" to sourceEvictions,
            "history_evictions" to sourceHistoryEvictions,"invalid_flows" to sourceInvalid,"packet_limit" to limit,
            "seconds" to (System.currentTimeMillis()-begin)/1000.0,"input_bytes" to inputs.sumOf{it.first.length()},"captures" to inputs.size)
        File(prefix.path+".ready.json").writeText(AlignedContract.json(result));println(AlignedContract.json(result))
    }
}
