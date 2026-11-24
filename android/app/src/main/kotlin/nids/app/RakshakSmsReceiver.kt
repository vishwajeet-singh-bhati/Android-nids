package nids.app

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.provider.Telephony

/** Protected by BROADCAST_SMS in the manifest. No inbox access or raw-text persistence. */
class RakshakSmsReceiver: BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != Telephony.Sms.Intents.SMS_RECEIVED_ACTION ||
            !SafetyControls.enabled(context, SafetyControls.INCOMING)) return
        val parts = Telephony.Sms.Intents.getMessagesFromIntent(intent) ?: return
        val text = parts.joinToString("") { it.messageBody.orEmpty() }
        if (text.isBlank()) return
        SafetyAnalysisService.submit(context, text, "message", "incoming", parts.firstOrNull()?.originatingAddress)
    }
}
