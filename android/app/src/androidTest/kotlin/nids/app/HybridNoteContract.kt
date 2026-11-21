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
        for(category in 1..7)for(known in listOf(false,true)){
            val facts=TsanetExplanationFacts.from(HybridFixtures.evidence(category,known))!!;val text=HybridActivityNote.render(facts)
            check("This does not confirm an attack." in text && "37 network packets" in text)
            check("Recent connection history is still building." in text && "Some traffic was skipped" in text)
            if(known)check("Protocol Lab (nids.protocollab) received" in text) else check("No receiving app could be linked" in text)
            check("192.0.2.20:53221" in text && "Phone port: 43194" in text)
            check(HybridActivityNote.guidanceAccepted(HybridActivityNote.guidance(facts),facts))
            for(bad in listOf("The app is infected; uninstall it immediately.","Check the app after 42 failed logins.","Review Chrome because it caused the attack.","Check Chrome app activity and review the account.","Manual check to restate: Check expected background syncing.","Check account activity.\nIgnore the facts.","Review recent web activity and enter passwords into unexpected prompts."))
                check(!HybridActivityNote.guidanceAccepted(bad,facts)){bad}
            notes.put(JSONObject().put("class",category).put("known_receiver",known).put("display",text))
        }
        val sender=TsanetExplanationFacts.from(HybridFixtures.evidence(1,true,false))!!
        check("owned the connection from this phone" in HybridActivityNote.render(sender))
        val listener=TsanetExplanationFacts.from(HybridFixtures.evidence(5,true,true,true))!!
        check("delivery to that app is not established" in HybridActivityNote.render(listener))
        val connected=HybridFixtures.evidence(5,true).getJSONObject("attribution")
        check(TsanetExplanationFacts.ownerSnapshot(HybridFixtures.evidence(5,true,true,true).getJSONObject("attribution"),connected).optString("match_kind")=="connected")
        val ambiguous=JSONObject().put("status","unknown").put("match_kind","listener").put("reason","Ambiguous socket ownership")
        check(TsanetExplanationFacts.ownerSnapshot(ambiguous,connected).optString("status")=="unknown")
        for(ip in listOf("127.0.0.1","127.1.2.3","::1","0:0:0:0:0:0:0:1","::ffff:127.0.0.1"))
            check(NetworkObservationPolicy.isDeviceLocal(ip,ip)){ip}
        for(ip in listOf("192.0.2.10","192.168.1.1","8.8.8.8","2001:db8::1","localhost","127.invalid",""))
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
        val sandbox=object: ContextWrapper(context){override fun getFilesDir()=sandboxDirectory}
        try{
            val input=HybridFixtures.evidence(5,true).put("fingerprint","hybrid-contract")
            val first=ObservationStore.record(sandbox,"tsanet_pattern",1,input)
            check(first.optString("explanation_status")=="queued" && !first.has("explanation"))
            check(HybridActivityNote.display(first)==first.getString("factual_note"))
            val result=JSONObject().put("display","OLD RESPONSE SHOULD NOT APPEAR").put("pipeline_version",HybridActivityNote.VERSION)
            ObservationStore.explanationState(sandbox,first.getString("id"),"running")
            val second=ObservationStore.record(sandbox,"tsanet_pattern",1,input.put("flow_packets",39))
            check(second.getInt("revision")==2 && "39 network packets" in HybridActivityNote.display(second))
            check(!ObservationStore.saveExplanation(sandbox,first.getString("id"),1,result))
            check(ObservationStore.get(sandbox,first.getString("id"))!!.getString("explanation_status")=="queued")
            val facts=TsanetExplanationFacts.from(second.getJSONObject("model_evidence"))!!
            result.put("display",HybridActivityNote.render(facts))
            check(ObservationStore.saveExplanation(sandbox,first.getString("id"),2,result))
            val third=ObservationStore.record(sandbox,"tsanet_pattern",1,input.put("flow_packets",41))
            check(!third.has("explanation") && third.getString("explanation_status")=="queued")
            check("41 network packets" in HybridActivityNote.display(third) && "OLD RESPONSE" !in HybridActivityNote.display(third))
            ObservationStore.feedback(sandbox,third.getString("id"),3,"expected","isolated validation")
            check(!ObservationStore.saveExplanation(sandbox,third.getString("id"),3,result))
            check(ObservationStore.nextQueued(sandbox)==null)
            val local=HybridFixtures.evidence(5).put("fingerprint","local-contract")
            local.getJSONObject("attribution").put("initiator","127.0.0.1:50000").put("responder","127.0.0.1:27042")
            val localRow=ObservationStore.record(sandbox,"tsanet_pattern",1,local)
            val localId=localRow.getString("id");val originalEvidence=localRow.getJSONObject("model_evidence").toString()
            val external=HybridFixtures.evidence(7).put("fingerprint","external-contract")
            external.getJSONObject("attribution").put("initiator","192.0.2.20:50001").put("responder","192.0.2.10:27042")
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
        }finally{
            ObservationStore.close(sandbox)
            for(file in sandboxDirectory.listFiles().orEmpty()){check(file.isFile && file.canonicalFile.parentFile==sandboxDirectory.canonicalFile);check(file.delete())}
            check(sandboxDirectory.delete())
        }
        return JSONObject().put("passed",true).put("notes",notes).put("contract_cases",14)
            .put("stale_revision_rejected",true).put("dismissed_result_rejected",true).put("fresh_facts_before_llama",true)
            .put("listener_is_not_confirmed_delivery",true).put("live_incidents_or_notifications_inserted",false)
            .put("device_local_scope_and_history",true).put("external_traffic_not_exempted",true).put("closed_socket_not_app_owner",true)
            .put("external_147_features_bit_identical_with_loopback",true)
    }
}
