package nids.contractcheck

import android.app.Activity
import android.app.Instrumentation
import android.os.Bundle
import java.io.File
import nids.core.*

/** Offline fixtures only; this APK has no INTERNET permission and targets itself. */
class ContractInstrumentation: Instrumentation(){
    private var options=Bundle()
    override fun onCreate(arguments: Bundle?){options=arguments ?: Bundle();start()}
    override fun onStart(){
        val result=Bundle()
        try{
            if(options.getString("mode")=="hybrid_contract"){
                val report=nids.app.HybridNoteContract.run(targetContext)
                    .put("source_manifest",org.json.JSONObject(targetContext.assets.open("hybrid_sources.json").bufferedReader().use{it.readText()}))
                    .put("isolated_package",targetContext.packageName)
                File(targetContext.filesDir,"hybrid_contract_validation.json").writeText(report.toString(2))
                result.putString("report",report.toString());finish(Activity.RESULT_OK,result);return
            }
            val checks=AlignedCheck.run()+mapOf("source_manifest" to targetContext.assets.open("contract_sources.json").bufferedReader().use{it.readText()})
            val name=options.getString("input")
            val report=if(name==null)checks else{
                require(name.matches(Regex("[A-Za-z0-9_.-]+")))
                checks+mapOf("replay" to AlignedReplay.run(File(targetContext.filesDir,name),File(targetContext.filesDir,"features.tsv")))
            }
            File(targetContext.filesDir,"contract_check.json").writeText(AlignedContract.json(report))
            result.putString("report",AlignedContract.json(report));finish(Activity.RESULT_OK,result)
        }catch(error: Throwable){result.putString("error",error.toString());finish(Activity.RESULT_CANCELED,result)}
    }
}
