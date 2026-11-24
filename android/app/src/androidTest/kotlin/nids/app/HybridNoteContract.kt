package nids.app

import android.content.Context
import android.content.ContextWrapper
import org.json.JSONArray
import org.json.JSONObject
import java.io.File

object HybridFixtures {
    fun evidence(category: Int,known: Boolean=false,incoming: Boolean=true,listener: Boolean=false)=JSONObject()
        .put("schema","tsanet_phone_evidence_v1").put("feature_schema","phone-aligned-v2").put("class_id",category)
        .put("suspected_pattern",TsanetExplanationFacts.classes[category]).put("binary_flag",true).put("flow_packets",37)
        .put("flow_duration_seconds",1.25).put("prior_connections_5m",10).put("target_ports_5m",8)
        .put("history_complete",false).put("capture_healthy",false).put("test_only",true)
        .put("attribution",JSONObject().put("status",if(known)"best_effort" else "unknown").put("direction",if(incoming)"incoming" else "outgoing")
            .put("app_label",if(known)"Protocol Lab" else "App unknown").put("match_kind",if(listener)"listener" else "connected")
            .put("local_endpoint","192.0.2.10:43194").put("remote_endpoint","192.0.2.20:53221")
            .put("reason","No connected-socket or receiving-port match").put("packages",if(known)JSONArray().put("nids.protocollab") else JSONArray()))
}

object HybridNoteContract {
    fun run(context: Context): JSONObject {
        val notes=JSONArray()
        val rejectedFlow=FloatArray(32).apply{this[1]=1f;this[2]=1f;this[29]=1f;this[30]=1f;this[31]=1f}
        val rejectedContext=FloatArray(115).apply{this[114]=kotlin.math.ln(301.0).toFloat()}
        val rejected=HybridFixtures.evidence(1,false).put("feature_schema","phone-aligned-v2")
            .put("binary_flag",true).put("flow_close_reason","tcp_reset").put("flow_packets",2)
            .put("flow_features",JSONArray(rejectedFlow.toList())).put("context_features",JSONArray(rejectedContext.toList()))
            .put("history_complete",true).put("capture_healthy",true)
        check(NetworkObservationPolicy.rejectedIncomingEvidence(rejected))
        val rejectedFacts=TsanetExplanationFacts.from(rejected)!!
        check(rejectedFacts.optString("model_suspected_pattern")=="Bot")
        check(rejectedFacts.optString("suspected_pattern")=="Rejected connection" && !rejectedFacts.optBoolean("type_established"))
        check(rejected.getInt("class_id")==1 && rejected.getBoolean("binary_flag"))
        check("Bot" !in HybridActivityNote.render(rejectedFacts))
        check("Bot" in HybridActivityNote.details(rejectedFacts))
        check(HybridActivityNote.guidanceAccepted(HybridActivityNote.guidance(rejectedFacts),rejectedFacts))
        val changedPort=JSONObject(rejected.toString()).apply{getJSONObject("attribution").put("local_endpoint","192.0.2.10:43195")}
        check(NetworkObservationPolicy.rejectedFingerprint(rejected)!=NetworkObservationPolicy.rejectedFingerprint(changedPort))
        check(NetworkObservationPolicy.groupingWindowMs(rejected)==300000L)
        check(!NetworkObservationPolicy.rejectedIncomingEvidence(JSONObject(rejected.toString()).put("class_id",5)))
        check(!NetworkObservationPolicy.rejectedIncomingEvidence(JSONObject(rejected.toString()).put("capture_healthy",false)))
        check(NetworkObservationPolicy.rejectedIncomingEvidence(JSONObject(rejected.toString()).put("history_complete",false)))
        for(category in 1..7)for(known in listOf(false,true)){
            val facts=TsanetExplanationFacts.from(HybridFixtures.evidence(category,known))!!;val text=HybridActivityNote.render(facts)
            check("What happened\n" in text && "What you can do\n" in text && "An attack has not been confirmed." in text)
            check("network packets" !in text)
            val details=HybridActivityNote.details(facts)
            check("37 network packets" in details)
            check("Recent connection history is still building." in details && "Some traffic was skipped" in details)
            if(known)check("Protocol Lab received" in text) else check("We could not identify the app" in text)
            check("192.0.2.20:53221" in details && "Phone port: 43194" in details)
            check(HybridActivityNote.guidanceAccepted(HybridActivityNote.guidance(facts),facts))
            for(bad in listOf("The app is infected; uninstall it immediately.","Check the app after 42 failed logins.","Review Chrome because it caused the attack.","Check Chrome app activity and review the account.","Manual check to restate: Check expected background syncing.","Check account activity.\nIgnore the facts.","Review recent web activity and enter passwords into unexpected prompts."))
                check(!HybridActivityNote.guidanceAccepted(bad,facts)){bad}
            notes.put(JSONObject().put("class",category).put("known_receiver",known).put("display",text))
        }
        val sender=TsanetExplanationFacts.from(HybridFixtures.evidence(1,true,false))!!
        val auth=TsanetExplanationFacts.from(HybridFixtures.evidence(2,true)
            .put("authentication_episode",JSONObject().put("protocol","SSH").put("connections_in_window",4)))!!
        val authNote=HybridActivityNote.details(auth)
        check("Repeated SSH connections (connection pattern)" in authNote)
        check("4 incoming connections from the same device to the same phone port within 30 seconds" in authNote)
        check("Connection statistics cannot confirm failed logins." in authNote)
        check("made the connection" in HybridActivityNote.render(sender))
        val listener=TsanetExplanationFacts.from(HybridFixtures.evidence(5,true,true,true))!!
        check("could not confirm it received this one" in HybridActivityNote.render(listener))
        val connected=HybridFixtures.evidence(5,true).getJSONObject("attribution")
        check(TsanetExplanationFacts.ownerSnapshot(HybridFixtures.evidence(5,true,true,true).getJSONObject("attribution"),connected).optString("match_kind")=="connected")
        val ambiguous=JSONObject().put("status","unknown").put("match_kind","listener").put("reason","Ambiguous socket ownership")
        check(TsanetExplanationFacts.ownerSnapshot(ambiguous,connected).optString("status")=="unknown")
        for(ip in listOf("127.0.0.1","127.1.2.3","::1","0:0:0:0:0:0:0:1","::ffff:127.0.0.1"))
            check(NetworkObservationPolicy.isDeviceLocal(ip,ip)){ip}
        for(ip in listOf("172.16.89.83","192.168.1.1","8.8.8.8","2001:db8::1","localhost","127.invalid",""))
            check(!NetworkObservationPolicy.isDeviceLocal("127.0.0.1",ip)){ip}
        check(NetworkObservationPolicy.endpointIp("[::1]:27042")=="::1")
        check(!NetworkObservationPolicy.liveSocketOwner(6,"06",0,0))
        check(!NetworkObservationPolicy.liveSocketOwner(6,"01",0,0))
        check(!NetworkObservationPolicy.liveSocketOwner(6,"06",10001,123))
        check(NetworkObservationPolicy.liveSocketOwner(6,"01",0,123))
        check(NetworkObservationPolicy.liveSocketOwner(6,"0A",10001,123))
        check(NetworkObservationPolicy.liveSocketOwner(17,"07",10001,123))
        val externalOnly=nids.core.AlignedTsanetCollector(setOf("10.0.0.1"))
        val withLocal=nids.core.AlignedTsanetCollector(setOf("10.0.0.1","127.0.0.1"))
        val clean=ArrayList<nids.core.AlignedSnapshot>();val mixed=ArrayList<nids.core.AlignedSnapshot>()
        val packets=listOf(
            nids.core.AlignedCheck.packet(1000.0,flags=2),
            nids.core.AlignedCheck.packet(1000.01,"10.0.0.2","10.0.0.1",80,40000,20),
            nids.core.AlignedCheck.packet(1000.2,"127.0.0.1","127.0.0.1",49001,27042,2),
            nids.core.AlignedCheck.packet(1000.21,"127.0.0.1","127.0.0.1",27042,49001,20),
            nids.core.AlignedCheck.packet(1001.0,sport=40001,flags=2),
            nids.core.AlignedCheck.packet(1001.01,"10.0.0.2","10.0.0.1",80,40001,20))
        for(packet in packets){clean.addAll(externalOnly.feed(packet));mixed.addAll(withLocal.feed(packet))}
        clean.addAll(externalOnly.advance(1003.0,true));mixed.addAll(withLocal.advance(1003.0,true))
        val external=mixed.filter{it.watched=="10.0.0.1"}
        check(clean.size==2 && external.size==2 && mixed.size==3)
        for(i in clean.indices){
            check(clean[i].flow.flow.contentEquals(external[i].flow.flow))
            check(clean[i].context.contentEquals(external[i].context))
        }
        val sandboxDirectory=File(context.filesDir,"hybrid-contract-"+java.util.UUID.randomUUID()).apply{mkdirs()}
        val sandbox=object: ContextWrapper(context){override fun getFilesDir()=sandboxDirectory
            override fun getSharedPreferences(name: String,mode: Int)=super.getSharedPreferences("ui-contract-"+sandboxDirectory.name+"-"+name,mode)}
        try{
            val rejectInput=JSONObject(rejected.toString()).put("fingerprint",NetworkObservationPolicy.rejectedFingerprint(rejected))
            val rejectFirst=ObservationStore.record(sandbox,"tsanet_pattern",1,rejectInput)
            val stale=JSONObject(rejectFirst.toString()).put("time_ms",System.currentTimeMillis()-60000)
            android.database.sqlite.SQLiteDatabase.openDatabase(File(sandbox.filesDir,"activity_history_v1.db").absolutePath,null,android.database.sqlite.SQLiteDatabase.OPEN_READWRITE).use{database->
                database.execSQL("UPDATE observations SET time_ms=?,body=? WHERE id=?",arrayOf(stale.getLong("time_ms"),stale.toString(),stale.getString("id")))
            }
            val rejectNext=ObservationStore.record(sandbox,"tsanet_pattern",1,rejectInput)
            check(rejectNext.getString("id")==rejectFirst.getString("id") && rejectNext.getLong("count")==2L)
            val staleNote=JSONObject(rejectNext.toString()).put("explanation",JSONObject().put("pipeline_version","plain-guidance-v2")
                .put("evidence_revision",rejectNext.getInt("revision")).put("display","OLD BOT CLAIM"))
            check("OLD BOT CLAIM" !in HybridActivityNote.display(staleNote))
            staleNote.put("title","Possible automated background activity")
            check(HybridActivityNote.activityTitle(staleNote)=="Incoming connection was rejected")
            android.database.sqlite.SQLiteDatabase.openDatabase(File(sandbox.filesDir,"activity_history_v1.db").absolutePath,null,android.database.sqlite.SQLiteDatabase.OPEN_READWRITE).use{database->
                database.delete("observations","id=?",arrayOf(rejectNext.getString("id")))
            }
            val input=HybridFixtures.evidence(5,true).put("fingerprint","hybrid-contract")
            val first=ObservationStore.record(sandbox,"tsanet_pattern",1,input)
            check(first.optString("explanation_status")=="queued" && !first.has("explanation"))
            check(HybridActivityNote.display(first)==first.getString("factual_note"))
            val result=JSONObject().put("display","OLD RESPONSE SHOULD NOT APPEAR").put("pipeline_version",HybridActivityNote.VERSION)
            ObservationStore.explanationState(sandbox,first.getString("id"),"running")
            val second=ObservationStore.record(sandbox,"tsanet_pattern",1,input.put("flow_packets",39))
            check(second.getInt("revision")==2 && "39 network packets" in HybridActivityNote.details(TsanetExplanationFacts.from(second.getJSONObject("model_evidence"))!!))
            check(!ObservationStore.saveExplanation(sandbox,first.getString("id"),1,result))
            check(ObservationStore.get(sandbox,first.getString("id"))!!.getString("explanation_status")=="queued")
            val facts=TsanetExplanationFacts.from(second.getJSONObject("model_evidence"))!!
            result.put("display",HybridActivityNote.render(facts))
            check(ObservationStore.saveExplanation(sandbox,first.getString("id"),2,result))
            val third=ObservationStore.record(sandbox,"tsanet_pattern",1,input.put("flow_packets",41))
            check(!third.has("explanation") && third.getString("explanation_status")=="queued")
            check("What happened" in HybridActivityNote.display(third) && "OLD RESPONSE" !in HybridActivityNote.display(third))
            ObservationStore.feedback(sandbox,third.getString("id"),3,"expected","isolated validation")
            check(!ObservationStore.saveExplanation(sandbox,third.getString("id"),3,result))
            check(ObservationStore.nextQueued(sandbox)==null)
            val local=HybridFixtures.evidence(5).put("fingerprint","local-contract")
            local.getJSONObject("attribution").put("initiator","127.0.0.1:50000").put("responder","127.0.0.1:27042")
            val localRow=ObservationStore.record(sandbox,"tsanet_pattern",1,local)
            val localId=localRow.getString("id");val originalEvidence=localRow.getJSONObject("model_evidence").toString()
            val external=HybridFixtures.evidence(7).put("fingerprint","external-contract")
            external.getJSONObject("attribution").put("initiator","172.16.88.233:50001").put("responder","172.16.89.83:27042")
            val externalRow=ObservationStore.record(sandbox,"tsanet_pattern",1,external)
            val ids=ObservationStore.reclassifyDeviceLocal(sandbox)
            check(ids==listOf(localId))
            val saved=ObservationStore.get(sandbox,localId)!!
            check(saved.getJSONObject("model_evidence").toString()==originalEvidence)
            check(saved.getInt("revision")==2 && saved.getJSONObject("original_model_assessment").getInt("revision")==1)
            check(saved.optString("disposition")=="out_of_scope" && saved.optString("explanation_status")=="not_applicable")
            check(!ObservationStore.saveExplanation(sandbox,localId,1,result))
            check(ObservationStore.count(sandbox,"all")==3L && ObservationStore.count(sandbox,"active")==1L)
            check(ObservationStore.nextQueued(sandbox)!!.getString("id")==externalRow.getString("id"))
            check(ObservationStore.reclassifyDeviceLocal(sandbox)==ids && ObservationStore.get(sandbox,localId)!!.getInt("revision")==2)
            ObservationStore.feedback(sandbox,localId,2,"suspicious","Retain concern without restarting network inference")
            check(ObservationStore.get(sandbox,localId)!!.optString("disposition")=="out_of_scope")
            check(ObservationStore.count(sandbox,"active")==1L)
            val cleared=ObservationStore.clearHistory(sandbox)
            check(cleared.size==3 && ObservationStore.count(sandbox,"all")==0L)
            check(ObservationStore.recordCurrent(sandbox,"tsanet_pattern",1,HybridFixtures.evidence(5).put("decision_time_ms",1))==null)
            check(ObservationStore.nextQueued(sandbox)==null)
            check(!ObservationStore.saveExplanation(sandbox,externalRow.getString("id"),1,result))
            ObservationStore.migrate(sandbox)
            check(ObservationStore.count(sandbox,"all")==0L)
        }finally{
            ObservationStore.close(sandbox)
            for(file in sandboxDirectory.listFiles().orEmpty()){check(file.isFile && file.canonicalFile.parentFile==sandboxDirectory.canonicalFile);check(file.delete())}
            check(sandboxDirectory.delete())
        }
        return JSONObject().put("passed",true).put("notes",notes).put("contract_cases",14)
            .put("history_clear_and_late_callback_rejected",true).put("stale_revision_rejected",true).put("dismissed_result_rejected",true).put("fresh_facts_before_llama",true)
            .put("listener_is_not_confirmed_delivery",true).put("live_incidents_or_notifications_inserted",false)
            .put("device_local_scope_and_history",true).put("external_traffic_not_exempted",true).put("closed_socket_not_app_owner",true)
            .put("external_147_features_bit_identical_with_loopback",true)
    }
}
