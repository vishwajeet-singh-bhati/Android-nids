package nids.core

import java.io.BufferedInputStream
import java.io.InputStream

/** Offline container reader only. Packet interpretation remains the Android parser. */
class CaptureFileStream(input: InputStream){
    private val stream=if(input is BufferedInputStream)input else BufferedInputStream(input,1 shl 20)
    private var little=true
    private data class Interface(val link: Int,val resolution: Double,val offset: Double)
    private val interfaces=ArrayList<Interface>()
    private val classic: PcapStreamReader?
    init{
        stream.mark(4);val bytes=ByteArray(4);check(read(bytes));stream.reset()
        classic=if(bytes.contentEquals(byteArrayOf(10,13,13,10)))null else PcapStreamReader(stream)
    }
    private fun read(out: ByteArray): Boolean{var at=0;while(at<out.size){val n=stream.read(out,at,out.size-at);if(n<0){check(at==0){"Truncated capture"};return false};at+=n};return true}
    private fun discard(n: Int){check(n>=0);var left=n.toLong();while(left>0){val skipped=stream.skip(left);if(skipped>0)left-=skipped else{check(stream.read()>=0){"Truncated capture"};left--}}}
    private fun u16(b: ByteArray,o: Int)=if(little)(b[o].toInt() and 255) or ((b[o+1].toInt() and 255) shl 8) else ((b[o].toInt() and 255) shl 8) or (b[o+1].toInt() and 255)
    private fun u32(b: ByteArray,o: Int): Long{var n=0L;for(i in 0..3)n=n or ((b[o+i].toLong() and 255) shl (8*if(little)i else 3-i));return n}
    private fun u64(b: ByteArray,o: Int): Long{var n=0L;for(i in 0..7)n=n or ((b[o+i].toLong() and 255) shl (8*if(little)i else 7-i));return n}
    fun next(): Frame?{
        classic?.let{return it.next()}
        while(true){
            val header=ByteArray(8);if(!read(header))return null
            if(header.sliceArray(0..3).contentEquals(byteArrayOf(10,13,13,10))){
                val bom=ByteArray(4);check(read(bom));little=bom.contentEquals(byteArrayOf(77,60,43,26))
                check(little || bom.contentEquals(byteArrayOf(26,43,60,77))){"Invalid pcapng byte order"}
                val length=u32(header,4).toInt();check(length in 28..16777216 && length%4==0)
                discard(length-16);val tail=ByteArray(4);check(read(tail) && u32(tail,0).toInt()==length)
                interfaces.clear();continue
            }
            val type=u32(header,0).toInt();val length=u32(header,4).toInt()
            check(length in 12..16777216 && length%4==0){"Invalid pcapng block length"}
            if(type==6){
                val fields=ByteArray(20);check(read(fields));val id=u32(fields,0).toInt();check(id in interfaces.indices)
                val captured=u32(fields,12).toInt();val original=u32(fields,16).toInt()
                check(captured>=0 && captured<=length-32)
                val kept=minOf(captured,768);val data=ByteArray(kept);check(read(data));discard(length-32-kept)
                val tail=ByteArray(4);check(read(tail) && u32(tail,0).toInt()==length)
                val iface=interfaces[id];val ticks=u32(fields,4)*4294967296.0+u32(fields,8)
                return Frame(ticks*iface.resolution+iface.offset,iface.link,original,data)
            }
            val body=ByteArray(length-12);check(read(body));val tail=ByteArray(4);check(read(tail) && u32(tail,0).toInt()==length)
            if(type==1){
                check(body.size>=8);var resolution=1e-6;var offset=0.0;var at=8
                while(at+4<=body.size){val code=u16(body,at);val n=u16(body,at+2);at+=4;if(code==0)break;check(at+n<=body.size)
                    if(code==9 && n==1){val value=body[at].toInt() and 255;resolution=if(value and 128!=0)Math.pow(2.0,-(value and 127).toDouble()) else Math.pow(10.0,-value.toDouble())}
                    if(code==14 && n==8)offset=u64(body,at).toDouble()
                    at+=(n+3)/4*4
                }
                interfaces.add(Interface(u16(body,0),resolution,offset))
            }else if(type==2 || type==3)error("Unsupported pcapng packet block $type; refusing partial training input")
        }
    }
}
