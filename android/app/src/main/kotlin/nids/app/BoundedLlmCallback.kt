package nids.app

import org.pytorch.executorch.extension.llm.LlmCallback

/** Conservative text-callback ceiling; verify the native token count separately. */
internal class BoundedLlmCallback(
    private val limit: Int,
    private val stop: ()->Unit,
    private val downstream: LlmCallback
): LlmCallback {
    var tokenCallbacks=0; private set
    var receivedCallbacks=0; private set
    var limitReached=false; private set
    init{require(limit>0)}
    override fun onResult(value: String){
        receivedCallbacks++
        // Some runners send a final text/newline notification after stop().
        // Count only forwarded token callbacks against this output budget.
        if(limitReached){stop();return}
        downstream.onResult(value)
        tokenCallbacks++
        if(tokenCallbacks>=limit){limitReached=true;stop()}
    }
    override fun onStats(value: String)=downstream.onStats(value)
    override fun onError(code: Int,message: String)=downstream.onError(code,message)
}
