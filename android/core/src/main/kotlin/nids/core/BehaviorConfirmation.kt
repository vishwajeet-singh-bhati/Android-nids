package nids.core

/** Temporal confirmation of learned scores; no port or rate attack rules. */
class BehaviorConfirmation {
    private val positive=HashMap<String,Long>()
    var stateResets=0L;private set
    fun clear(){positive.clear()}
    fun accept(host: String,end: Long,isPositive: Boolean): Boolean {
        if(!isPositive){positive.remove(host);return false}
        if(positive.size>=10000 && !positive.containsKey(host)){
            positive.entries.removeAll{it.value<end-60}
            if(positive.size>=10000){positive.clear();stateResets++}
        }
        val previous=positive.put(host,end)
        return previous!=null && previous==end-1
    }
}
