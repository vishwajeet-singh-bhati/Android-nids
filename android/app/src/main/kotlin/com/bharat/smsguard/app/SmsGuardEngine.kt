package com.bharat.smsguard.app

import android.content.Context
import com.bharat.smsguard.tier1.PortableLinearModel
import com.bharat.smsguard.tier1.RiskPolicy
import com.bharat.smsguard.tier1.Tier1Detector

/**
 * Lazily loads the verified portable word TF-IDF model bundled in assets.
 * All inference stays in this process; there is no network path.
 */
object SmsGuardEngine {
    @Volatile
    private var detector: Tier1Detector? = null

    fun get(context: Context): Tier1Detector {
        detector?.let { return it }
        return synchronized(this) {
            detector ?: build(context.applicationContext).also { detector = it }
        }
    }

    private fun build(context: Context): Tier1Detector {
        val hashes = org.json.JSONObject(context.assets.open("sms/manifest.json").bufferedReader().use { it.readText() })
        val json = nids.app.SafetyAssets.install(context, "sms/portable_model.json", hashes.getString("portable_model.json")).readText()
        return Tier1Detector(
            model = PortableLinearModel.fromJson(json),
            policy = RiskPolicy.production(),
        )
    }

    fun resetForTest() {
        detector = null
    }
}
