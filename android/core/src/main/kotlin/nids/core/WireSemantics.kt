package nids.core

import java.net.URLDecoder

/** Bounded cleartext header observations; no credentials or raw text leave this object.
 * Absence is not an authentication success. Encrypted HTTP is never decoded.
 */
class WireSemantics{
    val values=FloatArray(18)
    private class Prefix{val text=StringBuilder();var expected: Long?=null;var scanned=0;var http=false;var done=false}
    private val directions=arrayOf(Prefix(),Prefix())
    fun push(p: ParsedPacket,forward: Boolean){
        if(p.payloadLen>0)values[10]++
        if(p.ipProto!=6 || p.payload.isEmpty())return
        val state=directions[if(forward)0 else 1]
        if(state.done)return
        var offset=0
        val expected=state.expected
        if(expected!=null){
            val delta=(p.seq-expected) and 0xffffffffL
            if(delta>=0x80000000L){values[11]++;val overlap=((expected-p.seq) and 0xffffffffL).toInt();offset=minOf(overlap,p.payload.size)}
            else if(delta>0){values[13]++;return}
        }
        val size=p.payload.size-offset
        state.expected=(p.seq+p.payload.size) and 0xffffffffL
        if(size<=0)return
        if(state.text.isEmpty() && p.payload.size>=3){
            if((p.payload[0].toInt() and 255) in 20..23 && (p.payload[1].toInt() and 255)==3)values[8]=1f
        }
        if(values[8]>0)return
        if(state.text.length>=4096){values[12]=1f;return}
        val amount=minOf(size,4096-state.text.length)
        state.text.append(String(p.payload,offset,amount,Charsets.ISO_8859_1))
        if(size>amount)values[12]=1f
        if(p.payloadLen>p.payload.size){values[13]++;state.expected=(p.seq+p.payloadLen) and 0xffffffffL}
        while(true){
            val end=state.text.indexOf("\n",state.scanned)
            if(end<0)break
            val line=state.text.substring(state.scanned,end).trimEnd('\r');state.scanned=end+1
            inspect(line)
            if(line.startsWith("HTTP/1.") || Regex("^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH) ").containsMatchIn(line))state.http=true
            if(line.isEmpty() && state.http){state.done=true;break}
        }
        if(p.payloadLen>p.payload.size && state.scanned<state.text.length)state.text.delete(state.scanned,state.text.length)
    }
    private fun inspect(line: String){
        val lower=line.lowercase()
        if(line.startsWith("HTTP/1.")){
            values[1]++;values[9]=1f
            val status=line.split(' ').getOrNull(1)?.toIntOrNull() ?: 0
            if(status==401 || status==403)values[2]++
            if(status in 400..499)values[3]++
            if(status in 500..599)values[4]++
        }
        if(Regex("^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH) ").containsMatchIn(line)){
            values[0]++;values[9]=1f
            var path=line.split(' ').getOrElse(1){""}.take(2048)
            repeat(2){path=try{URLDecoder.decode(path,"UTF-8")}catch(_: Exception){path}}
            val text=path.lowercase()
            if(listOf("login","signin","sign-in","/auth","/session").any{it in text})values[5]++
            if(Regex("(?:['\"]\\s*(?:or|and)\\s+|union\\s+(?:all\\s+)?select|(?:sleep|benchmark)\\s*\\()").containsMatchIn(text))values[6]++
            if(listOf("<script","javascript:","onerror=","onload=").any{it in text})values[7]++
        }
        if(lower.startsWith("authorization: basic "))values[14]=1f
        if(line.startsWith("SSH-"))values[16]=1f
        if(Regex("^(USER |PASS |220[- ])").containsMatchIn(line))values[17]=1f
        if(line.length>1000)values[15]=1f
    }
}

object AlignedPacketParser{
    const val IP_PREFIX=640
    fun decode(frame: Frame,stats: ParseStats?=null): ParsedPacket?{
        val b=frame.data
        fun u16(i: Int)=((b[i].toInt() and 255) shl 8) or (b[i+1].toInt() and 255)
        var offset=when(frame.linktype){1->14;113->16;276->20;0->4;101,12,14,228,229->0;else->-1}
        if(frame.linktype==1 && b.size>=14){var et=u16(12);repeat(2){if(et in setOf(0x8100,0x88a8,0x9100) && b.size>=offset+4){et=u16(offset+2);offset+=4}}}
        if(offset<0 || b.size<=offset){stats?.unsupportedLink=(stats?.unsupportedLink ?: 0)+1;return null}
        val ip=b.copyOfRange(offset,minOf(b.size,offset+IP_PREFIX))
        return PacketParser.decode(ip,101,frame.ts,512,setOf(53,5353),stats)
    }
}
