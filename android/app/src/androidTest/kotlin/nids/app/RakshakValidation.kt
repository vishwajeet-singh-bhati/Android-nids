package nids.app

import android.app.Activity
import android.app.Instrumentation
import android.content.Context
import android.content.ContextWrapper
import android.os.Bundle
import com.bharat.smsguard.app.SmsPipeline
import com.bharat.smsguard.tier1.BertTokenizer
import com.bharat.smsguard.tier1.SmsNormalizer
import com.bharat.smsguard.tier1.runTier1Parity
import com.bharat.smsguard.tier1.runFlagParity
import com.bharat.smsguard.tier1.runModelParity
import com.bharat.smsguard.tier1.runPolicyParity
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.time.Instant
import kotlin.math.abs

class RakshakValidation(private val test: Instrumentation, private val context: Context) {
    private fun fixture(name: String) = test.context.assets.open("rakshak/" + name).bufferedReader().use { it.readText() }
    private fun json(name: String) = JSONObject(fixture(name))
    private val output = File(context.filesDir, "rakshak_validation").apply { mkdirs() }
    private fun write(name: String, value: JSONObject) = File(output, name + ".json").writeText(value.toString(2))

    private fun equal(a: Any?, b: Any?): Boolean {
        if (a is JSONObject && b is JSONObject) return a.keys().asSequence().toSet() == b.keys().asSequence().toSet() &&
            a.keys().asSequence().all { equal(a.opt(it), b.opt(it)) }
        if (a is JSONArray && b is JSONArray) return a.length() == b.length() && (0 until a.length()).all { equal(a.opt(it), b.opt(it)) }
        if (a is Number && b is Number) return abs(a.toDouble() - b.toDouble()) < 1e-12
        return a == b
    }

    private fun urls(): JSONObject {
        val detector = LinkDetector.get(context)
        val now = Instant.parse(detector.config.getString("reference_time"))
        val failures = JSONArray()
        val maxima = mutableMapOf("features_raw" to 0.0, "features_scaled" to 0.0,
            "cnn_logit" to 0.0, "ngram_logit" to 0.0, "probability" to 0.0)
        var count = 0
        var scored = 0
        var decisions = 0
        val started = System.nanoTime()
        for (line in fixture("url_reference.jsonl").lineSequence().filter { it.isNotBlank() }) {
            val expected = JSONObject(line)
            val actual = detector.check(expected.getString("input"), expected.getString("input_type"), now, true)
            val errors = ArrayList<String>()
            fun same(field: String) {
                if (!equal(expected.opt(field), actual.opt(field))) errors.add(field)
            }
            same("decision"); same("source"); same("error")
            if (equal(expected.opt("decision"), actual.opt("decision")) && equal(expected.opt("source"), actual.opt("source"))) decisions++
            if (!expected.isNull("normalized")) {
                val e = expected.getJSONObject("normalized")
                val a = actual.getJSONObject("normalized")
                for (field in e.keys()) if (!equal(e.opt(field), a.opt(field))) errors.add("normalized." + field)
                same("site")
            }
            if (expected.has("token_ids")) {
                scored++
                // The reference stores the unpadded prefix. The mobile tensor is always length 256.
                val expectedIds = expected.getJSONArray("token_ids")
                val actualIds = actual.getJSONArray("token_ids")
                if (actualIds.length() != 256 || !(0 until 256).all {
                        actualIds.getLong(it) == if (it < expectedIds.length()) expectedIds.getLong(it) else 0L
                    }) errors.add("token_ids")
                for (field in listOf("features_raw", "features_scaled")) {
                    val e = expected.getJSONArray(field); val a = actual.getJSONArray(field)
                    val diff = (0 until e.length()).maxOf { abs(e.getDouble(it) - a.getDouble(it)) }
                    maxima[field] = maxOf(maxima.getValue(field), diff)
                    if (diff > 1e-6) errors.add(field)
                }
                val e = expected.getJSONObject("logits"); val a = actual.getJSONObject("logits")
                for ((field, name, tolerance) in listOf(
                    Triple("full_url_hybrid", "cnn_logit", 1e-4), Triple("char_ngram_lr", "ngram_logit", 1e-5))) {
                    val diff = abs(e.getDouble(field) - a.getDouble(field))
                    maxima[name] = maxOf(maxima.getValue(name), diff)
                    if (diff > tolerance) errors.add(name)
                }
                val diff = abs(expected.getDouble("probability") - actual.getDouble("probability"))
                maxima["probability"] = maxOf(maxima.getValue("probability"), diff)
                if (diff > 1e-5) errors.add("probability")
                same("model_outcome")
            }
            if (errors.isNotEmpty()) failures.put(JSONObject().put("row", count).put("fields", JSONArray(errors)))
            count++
            if (count % 128 == 0) write("urls_progress", JSONObject().put("rows", count).put("failures", failures))
        }
        return JSONObject().put("passed", failures.length() == 0).put("reference_rows", count)
            .put("scored_rows", scored).put("decision_source_matches", decisions).put("max_absolute_errors", JSONObject(maxima))
            .put("elapsed_ms", (System.nanoTime() - started) / 1e6).put("failures", failures)
    }

    private fun sms(): JSONObject {
        val directory = File(output, "tier1_fixtures").apply { mkdirs() }
        fun file(name: String): String = File(directory, name).also { it.writeText(fixture(name)) }.absolutePath
        val model = File(directory, "portable_model.json").also {
            it.writeText(context.assets.open("sms/portable_model.json").bufferedReader().use { r -> r.readText() })
        }.absolutePath
        runTier1Parity(arrayOf(file("synthetic_parity.tsv")))
        runFlagParity(arrayOf(file("synthetic_flags_parity.tsv")))
        runModelParity(arrayOf(model, file("synthetic_model_parity.tsv")))
        runPolicyParity(arrayOf(model, file("synthetic_policy_parity.tsv")))
        val cases = json("tier2_checks.json").getJSONArray("cases")
        val tokenizer = BertTokenizer(context.assets.open("sms/vocab.txt").bufferedReader().use { it.readLines() })
        val engine = SmsPipeline.tier2(context)
        var maximum = 0.0
        var classes = 0
        for (i in 0 until cases.length()) {
            val row = cases.getJSONObject(i)
            val normalized = SmsNormalizer.normalize(row.getString("text")).modelText
            check(normalized == row.getString("normalized")) { "SMS normalization at case " + i }
            val encoded = tokenizer.encode(normalized)
            check((0 until 128).all { encoded.ids[it] == row.getJSONArray("ids").getLong(it) &&
                encoded.mask[it] == row.getJSONArray("mask").getLong(it) && encoded.types[it] == 0L }) { "SMS tokens at case " + i }
            val logits = engine.logits(normalized)
            val expected = row.getJSONArray("logits")
            maximum = maxOf(maximum, (0..2).maxOf { abs(logits[it] - expected.getDouble(it)) })
            if (logits.indices.maxBy { logits[it] } == (0..2).maxBy { expected.getDouble(it) }) classes++
        }
        val benchmark = json("benchmark_suite.json").getJSONArray("cases")
        val counts = JSONObject()
        var routed = 0
        var failed = 0
        for (i in 0 until benchmark.length()) {
            val row = benchmark.getJSONObject(i)
            val result = SmsPipeline.analyze(context, row.getString("text"), row.optString("sender"))
            if (result.tier2Status == "completed") routed++
            if (result.tier2Status.startsWith("failed")) failed++
            val key = row.getString("label") + "->" + result.final.label + "/" + result.final.riskLevel
            counts.put(key, counts.optInt(key) + 1)
        }
        for (url in listOf("https://secure-bank.invalid@account-verify.invalid/login",
                "https://example.org/search?email=user@example.net")) {
            val normalized = SmsNormalizer.normalize(url)
            check(normalized.urls == listOf(url) && normalized.emails.isEmpty())
            check(normalized.modelText == "url_present") { "URL was damaged by email masking" }
        }
        val emailOnly = SmsNormalizer.normalize("Contact user@example.org")
        check(emailOnly.urls.isEmpty() && emailOnly.emails == listOf("user@example.org"))
        val routingChecks = JSONArray()
        for (text in listOf("You won", "You won!!!!!!", "Hi", "https://example.org/a", "https://example.org/a https://example.net/b")) {
            val result = SmsPipeline.analyze(context, text)
            check(result.final.riskLevel == "low" && result.tier2Status == "not_needed")
            routingChecks.put(JSONObject().put("risk", result.final.riskLevel).put("route", result.routingReason))
        }
        for (text in listOf("You won! Send your OTP now", "You won, pay a fee to claim", "You won https://example.org/claim")) {
            val first = com.bharat.smsguard.app.SmsGuardEngine.get(context).predict(text)
            check(com.bharat.smsguard.tier1.RoutineMessages.reason(first) == null)
        }
        val privateReviews = JSONArray()
        val privateFile = File(context.filesDir, "sms_review_private.json")
        if (privateFile.exists()) {
            val samples = JSONArray(privateFile.readText())
            for (i in 0 until samples.length()) {
                val sample = samples.getJSONObject(i)
                val result = SafetyPipeline.analyze(context, sample.getString("text"), "message")
                privateReviews.put(JSONObject().put("id", sample.getString("id")).put("result", result))
            }
        }
        return JSONObject().put("passed", classes == cases.length() && failed == 0)
            .put("routing_checks", routingChecks).put("dangerous_extensions_not_bypassed", 3)
            .put("url_email_boundary_cases", 3)
            .put("private_reviews", privateReviews)
            .put("tier1_parity_rows_each", 34).put("tier1_fixture_files", 4).put("tier2_cases", cases.length())
            .put("tokenization_matches", cases.length()).put("class_matches", classes)
            .put("maximum_logit_difference", maximum).put("strict_logit_tolerance_0_05_passed", maximum <= .05)
            .put("benchmark_scenarios", benchmark.length()).put("tier2_routed", routed)
            .put("tier2_failures", failed).put("benchmark_counts", counts)
            .put("scope", "Bundled synthetic regression cases; no independent SMS accuracy claim.")
    }

    private fun contract(): JSONObject {
        val suite = json("combine_cases.json")
        val tidy = suite.getJSONArray("tidy_link_cases")
        for (i in 0 until tidy.length()) {
            val row = tidy.getJSONObject(i)
            check(MessageLinkPolicy.tidy(row.getString("raw")) == if (row.isNull("expected")) null else row.getString("expected")) { "Tidy case " + i }
        }
        val combine = suite.getJSONArray("combine_cases")
        for (i in 0 until combine.length()) {
            val row = combine.getJSONObject(i)
            val links = row.getJSONArray("links").let { a -> (0 until a.length()).map { a.getString(it) } }
            val items = row.optJSONArray("link_results")?.let { a -> (0 until a.length()).map { a.getJSONObject(it) } }
            val actual = MessageLinkPolicy.combine(row.getJSONObject("sms"), links, items, row.optInt("not_checked"),
                row.optString("error").takeUnless { it == "null" || it.isEmpty() })
            check(equal(actual, row.getJSONObject("expected"))) { "Combine case " + i }
        }
        val directory = File(context.filesDir, "rakshak-contract-" + java.util.UUID.randomUUID()).apply { mkdirs() }
        val sandbox = object: ContextWrapper(context) {
            override fun getFilesDir() = directory
            override fun getApplicationContext(): Context = this
            override fun getSharedPreferences(name: String, mode: Int) = super.getSharedPreferences(directory.name + name, mode)
        }
        try {
            SafetyControls.set(sandbox, SafetyControls.SMS, false)
            SafetyControls.set(sandbox, SafetyControls.URL, false)
            val disabled = SafetyPipeline.analyze(sandbox, "Fixture text", "message")
            check(disabled.getString("analysis_status") == "disabled")
            check(SafetyPipeline.analyze(sandbox, "https://example.com", "url").getString("analysis_status") == "disabled")
            val facts = JSONObject().put("schema", SafetyNote.VERSION).put("domain", "message").put("risk_level", "high")
                .put("evidence_codes", JSONArray().put("OTP_REQUEST")).put("fingerprint", "isolated-safety")
                .put("phase", "preliminary")
            val early = ObservationStore.record(sandbox, "safety", 1, facts)
            check(early.getString("explanation_status") == "awaiting_checks" && ObservationStore.nextQueued(sandbox) == null)
            facts.put("phase", "final")
            val final = ObservationStore.record(sandbox, "safety", 1, facts)
            check(final.getString("id") == early.getString("id") && final.getInt("revision") == 2)
            check(ObservationStore.nextQueued(sandbox) != null)
            check("What happened" in HybridActivityNote.display(final) && "What you can do" in HybridActivityNote.display(final))
            check(!SafetyNote.accepted("Check this safe website and open it now", facts))
            check(!SafetyNote.accepted("Check the official website and provide your verification code", facts))
            check(!SafetyNote.accepted("Check the official website to verify this message", facts))
            check(SafetyNote.accepted("Check the official app and keep your verification code private.", facts))
            check("not checked" in SafetyNote.quietResult(JSONObject().put("evidence_codes", JSONArray().put("URL_CHECK_UNAVAILABLE"))))
            check("not be judged" in SafetyNote.quietResult(JSONObject().put("evidence_codes", JSONArray().put("URL_CHECK_UNCERTAIN"))))
            check("out of date" in SafetyNote.quietResult(JSONObject().put("threat_list_stale", true)))
            val interruptedFacts = JSONObject(facts.toString()).put("phase", "preliminary").put("fingerprint", "isolated-interrupted")
            val interrupted = ObservationStore.record(sandbox, "safety", 0, interruptedFacts)
            check(ObservationStore.hasInterruptedSafety(sandbox))
            ObservationStore.recoverInterruptedSafety(sandbox)
            val recovered = ObservationStore.get(sandbox, interrupted.getString("id"))!!
            check(recovered.getString("explanation_status") == "queued")
            check("when the app closed" in HybridActivityNote.display(recovered))
            ObservationStore.clearHistory(sandbox)
            check(!ObservationStore.saveExplanation(sandbox, final.getString("id"), 2, JSONObject()))
            val redacted = MessageLinkPolicy.redact("https://user:password@example.com/reset/private?token=secret#fragment", true)
            check("user" !in redacted && "password" !in redacted && "private" !in redacted && "secret" !in redacted && "fragment" !in redacted)
            check("846210" !in MessageLinkPolicy.redact("846210", true))
            val invalidView = MessageLinkPolicy.combine(JSONObject().put("risk_level", "low"), listOf("846210"),
                listOf(JSONObject().put("error", "invalid_input")), hostOnly = true)
            check("846210" !in invalidView.toString())
        } finally {
            ObservationStore.close(sandbox)
            directory.listFiles().orEmpty().forEach { check(it.isFile); it.delete() }
            directory.delete()
        }
        val detector = LinkDetector.get(context)
        // Public package has no redistributed threat feed; historical full-feed checks are documented.
        val future = detector.check("example.com", "domain", Instant.parse("2026-12-01T00:00:00Z"))
        check(future.getString("decision") == "UNCERTAIN" && !future.getBoolean("model_used") && future.getBoolean("threat_list_stale"))
        val failedLink = JSONObject().put("decision", "UNCERTAIN").put("model_status", "failed")
        val unavailable = MessageLinkPolicy.combine(JSONObject().put("risk_level", "low"),
            listOf("https://example.com"), listOf(failedLink), hostOnly = true)
        check(unavailable.getJSONObject("links").getString("status") == "unavailable")
        check(unavailable.getJSONObject("combined").getJSONArray("evidence").toString().contains("URL_CHECK_UNAVAILABLE"))
        return JSONObject().put("passed", true).put("combine_cases", combine.length()).put("tidy_cases", tidy.length())
            .put("disabled_detectors_explicit", true).put("preliminary_final_same_event", true)
            .put("history_clear_rejects_late_result", true).put("host_only_privacy", true)
            .put("threat_rule_independent_of_neural_model", "not_run_empty_public_feed").put("stale_domain_only_uncertain", true)
            .put("neural_failure_explicit", true).put("unsafe_guidance_rejected", true)
            .put("interrupted_preliminary_recovered", true).put("uncertain_links_visible_on_quiet_result", true)
    }

    fun run(mode: String) {
        val bundle = Bundle()
        var success = false
        try {
            val report = when (mode) {
                "rakshak_url_benchmark" -> UrlBenchmarkValidation.run(test, context)
                "rakshak_url_benchmark_raw" -> UrlBenchmarkValidation.run(test, context, true)
                "rakshak_urls" -> urls()
                "rakshak_sms" -> sms()
                "rakshak_service" -> RakshakServiceValidation.run(test, context)
                else -> contract()
            }.put("device", android.os.Build.MODEL).put("abi", android.os.Build.SUPPORTED_ABIS[0])
            write(mode, report)
            success = report.getBoolean("passed")
            bundle.putString("summary", report.toString())
        } catch (error: Throwable) {
            val report = JSONObject().put("passed", false).put("error", error.toString())
            write(mode, report)
            bundle.putString("error", error.toString())
        }
        test.finish(if (success) Activity.RESULT_OK else Activity.RESULT_CANCELED, bundle)
    }
}
