"""Author-owned synthetic challenge, not mined labels or independent ground truth.

No model predictions are consulted here. Related variants retain one scenario ID.
"""
import hashlib
import json
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent

# label | scenario category | language | message. All links are non-routable examples.
SPEC = r"""
ham|greeting|en|Hi
ham|greeting|en|Hello!
ham|greeting|en|Good afternoon
ham|greeting|en|Thanks
ham|greeting|hi-Latn|Namaste
ham|greeting|hi|नमस्ते
ham|personal|en|I reached the library. See you near the main entrance.
ham|personal|en|Can you bring the blue notebook tomorrow?
ham|personal|en|The meeting starts at 11:30 in room 204.
ham|personal|en|Please send the photos from our picnic when you are free.
ham|personal_money|en|I paid my share of yesterday's dinner. Thanks for organising it.
ham|personal_money|en|Please pay your share of dinner when convenient. We split the bill yesterday.
ham|personal_money|en|The rent payment for November is complete. Receipt is on the kitchen table.
ham|personal_money|en|We should compare fixed deposits and mutual funds before deciding.
ham|personal_money|en|Can we discuss the investment chapter in our economics assignment?
ham|personal|hi-Latn|Main ghar pahunch gaya. Kal subah milte hain.
ham|personal_money|hi-Latn|Kal ke dinner ka mera hissa bhej diya hai. Shukriya.
ham|personal|hi|मैं घर पहुँच गया हूँ। कल सुबह मिलते हैं।
ham|personal_money|hi|इस महीने का किराया जमा हो गया है। रसीद संभाल कर रखना।
ham|otp_notice|en|Your OTP is 645291. Do not share this code with anyone.
ham|otp_notice|en|OTP: 351782. Never disclose this code to a caller.
ham|otp_notice|en|Your verification code is 762451. Keep this code confidential.
ham|otp_notice|en|Your one-time password is 814672. Do not share it.
ham|otp_notice|hi-Latn|Aapka OTP 184726 hai. Ise kisi ke saath share mat karein.
ham|otp_notice|hi|आपका ओटीपी ६२१७४८ है। इसे किसी के साथ साझा न करें।
ham|transaction|en|Rs 725 has been credited to your savings account ending 7152.
ham|transaction|en|Your UPI payment of Rs 240 was successful. Reference 419275.
ham|transaction|en|Your monthly salary of Rs 42000 has been credited successfully.
ham|transaction|en|Your EMI of Rs 7200 was auto-debited successfully from your account.
ham|transaction|en|Refund of Rs 630 has been credited to the original payment method.
ham|transaction|hi-Latn|Aapke account mein Rs 3500 credit hue hain. Yeh sirf transaction suchna hai.
ham|delivery|en|Your parcel has been delivered. Thank you for shopping with us.
ham|delivery|en|Your order was delivered successfully at reception.
ham|delivery|en|Your groceries will arrive between 5 PM and 6 PM. No payment is due.
ham|service_notice|en|Your electricity bill is available in the official provider app. You can also pay at the billing office.
ham|service_notice|en|Your bank KYC review is due next month. Please visit your branch with identity documents.
ham|service_notice|en|Your bank statement is available in the app you already use. No reply is needed.
ham|service_notice|en|Your train reservation is confirmed. Coach S3, seat 42.
ham|service_notice|en|Your appointment is confirmed for Tuesday at the clinic. No online deposit is required.
ham|security_advice|en|Never share your OTP, PIN or password. A bank employee will not ask for these secrets.
ham|security_advice|en|Beware of anyone asking you to double your money in 2 days. Do not pay them.
ham|security_advice|en|Do not install APK files sent by unknown people claiming to offer a refund.
ham|security_advice|en|Fraud awareness: receiving money does not require sharing an OTP with a caller.
ham|security_advice|hi-Latn|OTP kisi ko mat batao. Bank ke naam par paise maangne wale se savdhaan raho.
ham|security_advice|hi|अपना ओटीपी और पिन किसी को न बताएं। अनजान लिंक से ऐप डाउनलोड न करें।
spam|retail_offer|en|Weekend sale: 25 percent off selected shoes in our stores. Unsubscribe to stop offers.
spam|retail_offer|en|New arrivals at the clothing store. Visit during opening hours for promotional prices.
spam|retail_offer|en|Buy two notebooks and get one free. Offer valid at participating outlets.
spam|retail_offer|en|Shop our seasonal sale at https://store.example.invalid/catalog . No prize or payment claim is required.
spam|telecom_offer|en|Recharge offer: compare our Rs 299 and Rs 399 plans in the official app.
spam|telecom_offer|en|Upgrade your broadband plan for additional monthly data. Terms and conditions apply.
spam|loan_offer|en|Pre-approved personal loan offer. Eligibility and interest rates are available at the branch. Terms apply.
spam|loan_offer|en|Home loan information session this Saturday. No application payment is requested in this message.
spam|investment_ad|en|Learn about mutual funds at our investor education seminar. Investments carry market risk.
spam|investment_ad|en|Trading course registration is open. No guaranteed returns are promised.
spam|reward_promotion|en|Get a chance to win a shopping voucher in our store lucky draw. No payment or personal details requested.
spam|reward_promotion|en|Earn loyalty points on eligible purchases at our stores. Terms apply.
spam|job_ad|en|Hiring office assistants. Apply through the company's careers page. We do not charge recruitment fees.
spam|job_ad|en|Part-time receptionist vacancy. Bring your resume to the office during working hours.
spam|subscription|en|Subscribe to our magazine and receive the first issue free. Cancel any time.
spam|retail_offer|hi-Latn|Is hafte kapdon par sale hai. Dukaan par aakar offers dekhein.
spam|telecom_offer|hi-Latn|Naya recharge plan official app mein dekhiye. Shartein lagu hain.
spam|retail_offer|hi|इस सप्ताह हमारी दुकान पर कपड़ों की सेल है। शर्तें लागू हैं।
spam|loan_offer|hi-Latn|Personal loan ki jankari branch mein milegi. Byaaj dar aur shartein pehle padhein.
spam|reward_promotion|en|Promotional draw announcement: entries close next week. Details available at the store counter.
smishing|otp_theft|en|I am your bank verification officer. Send me the OTP from your phone now to unblock your account.
smishing|otp_theft|en|Reply with your verification code so our agent can release your bank refund.
smishing|credential_theft|en|Your card is suspended. Provide the card PIN and CVV to our agent to restore access.
smishing|credential_theft|en|To receive your refund, enter your banking password at https://refund.example.invalid/login .
smishing|kyc|en|Your account will be blocked tonight. Update KYC and enter your password at https://kyc.example.invalid/verify .
smishing|kyc|en|PAN verification failed. Share your OTP with our representative immediately to keep your savings account active.
smishing|upi_refund|en|To receive the refund, scan our QR code and enter your UPI PIN. Approve the collect request now.
smishing|upi_refund|en|Your failed payment will be reversed after you send your UPI PIN to this number.
smishing|fake_credit|en|We credited Rs 5000 to you by mistake. Send it back to our private UPI ID immediately without checking your bank app.
smishing|advance_fee|en|Your loan is approved. Pay an upfront processing fee of Rs 950 to our agent's personal UPI ID before disbursal.
smishing|job_fee|en|Congratulations on your job selection. Pay a refundable security deposit to this personal wallet to receive your offer letter.
smishing|task_deposit|en|Earn Rs 4000 daily by rating videos. Join our Telegram task group and pay a deposit to unlock your earnings.
smishing|utility|en|Electricity disconnection tonight. Pay our officer using this personal payment link immediately: https://power.example.invalid/pay .
smishing|utility|en|To prevent your DTH connection from being disconnected, download our billing patch from https://dth.example.invalid/update.apk .
smishing|apk|en|Install https://benefit.example.invalid/refund.apk to receive your bank refund and grant it SMS access.
smishing|apk|en|SBI reward points expire now. Install the APK at https://points.example.invalid/app.apk and enter your card PIN.
smishing|delivery|en|Your parcel is held at customs. Pay the clearance fee at https://parcel.example.invalid/pay within one hour.
smishing|delivery|en|Delivery failed because your address is incomplete. Update your card details at https://courier.example.invalid/address .
smishing|lottery_fee|en|You won Rs 900000 in a lottery you never entered. Pay a release fee to our agent to claim it.
smishing|lottery_fee|en|Your international prize is ready. Share your banking password and OTP to activate the transfer.
smishing|government|en|Your government subsidy is approved. Pay a processing charge to our private UPI ID at https://grant.example.invalid/pay .
smishing|government|en|RBI official notice: your account will be frozen. Send your account password and OTP to the verification officer.
smishing|digital_arrest|en|CBI digital arrest notice. Transfer your savings to our safe account immediately and do not tell your family.
smishing|digital_arrest|en|A police case is filed against you. Pay Rs 12000 to settle it using the officer's personal wallet right now.
smishing|investment|en|Double your investment within three days. Deposit today and get guaranteed returns without risk.
smishing|investment|en|Triple your capital in 24 hours. Transfer money to join our guaranteed-profit group.
smishing|investment|en|Guaranteed 50 percent daily return. Send Rs 2000 to our wallet and recruit two friends to unlock withdrawal.
smishing|impersonation|en|This is your manager using a new number. Buy gift cards urgently and send the redemption codes to me privately.
smishing|impersonation|en|Your son is in police custody. Send money immediately to this private account and do not call him.
smishing|remote_access|en|To reverse a fraudulent bank charge, install our remote support app and tell the agent your screen-sharing code and banking password.
smishing|short_request|en|Send OTP now
smishing|short_request|en|Reply with your card PIN
smishing|otp_theft|hi-Latn|Main bank se bol raha hoon. Account kholne ke liye apna OTP abhi mujhe batao.
smishing|upi_refund|hi-Latn|Refund paane ke liye QR scan karo aur UPI PIN daalo. Collect request turant approve karo.
smishing|kyc|hi-Latn|Aaj bank account band hoga. KYC ke liye OTP share karo: https://bank.example.invalid/kyc .
smishing|job_fee|hi-Latn|Naukri pakki hai. Offer letter lene ke liye pehle personal UPI par registration fees bhejo.
smishing|investment|hi-Latn|Do din mein paisa double karenge. Abhi hamare wallet mein paise jama karo, guaranteed profit milega.
smishing|utility|hi-Latn|Aaj raat bijli kategi. Turant officer ke personal UPI par payment karo aur receipt bhejo.
smishing|otp_theft|hi|मैं बैंक अधिकारी हूँ। खाता चालू रखने के लिए अपना ओटीपी अभी मुझे बताएं।
smishing|upi_refund|hi|रिफंड लेने के लिए यह क्यूआर स्कैन करें और अपना यूपीआई पिन डालें।
smishing|investment|hi|दो दिन में पैसा दोगुना होगा। अभी हमारे निजी खाते में पैसे भेजें।
smishing|apk|hi|बैंक का रिफंड पाने के लिए https://refund.example.invalid/app.apk से ऐप डाउनलोड करें और ओटीपी दें।
uncertain|ambiguous_bill|en|Your bill is overdue. Pay at https://billing.example.invalid/account to avoid interruption.
uncertain|ambiguous_kyc|en|KYC update reminder: complete the process at https://service.example.invalid/kyc .
uncertain|ambiguous_delivery|en|Your delivery address needs confirmation. Visit https://track.example.invalid/address .
uncertain|ambiguous_reward|en|Get a chance to win $40000 in one click at https://reward.example.invalid/entry .
uncertain|ambiguous_money|en|Please send Rs 500 to this new number. I will explain later.
uncertain|ambiguous_security|en|Your login was blocked. Visit https://account.example.invalid/reset if you recognise this request.
uncertain|ambiguous_loan|hi-Latn|Loan approve ho gaya. Is link par details confirm karein: https://loan.example.invalid .
uncertain|ambiguous_utility|hi|आपका बिजली बिल बाकी है। भुगतान विवरण इस लिंक पर देखें: https://bill.example.invalid ।
"""

def main():
    rows = []
    for n, line in enumerate(SPEC.strip().splitlines(), 1):
        label, category, language, text = line.split("|", 3)
        rationale = {"ham": "Authored genuine/personal/service scenario; no fraudulent solicitation intended.",
            "spam": "Authored unwanted promotion without established deception; not automatically a scam.",
            "smishing": "Authored fraudulent solicitation or explicit secret/payment deception.",
            "uncertain": "Authenticity cannot be established from text alone; excluded from exact-label accuracy."}[label]
        for variant, message in [("original", text), ("spacing_case", "  " + text.upper().replace(" ", "  ") + "  ")]:
            rows.append({"id": f"scenario-{n:03d}-{variant}", "scenario_id": f"scenario-{n:03d}",
                "family": category, "language": language, "label": label, "text": message,
                "sender": "", "variant": variant, "source": "new_authored_synthetic_v1", "rationale": rationale})
    digest = hashlib.sha256(json.dumps(rows, ensure_ascii=False, sort_keys=True).encode()).hexdigest()
    payload = {"name": "Indian SMS scenario challenge v1", "version": 1, "rows_sha256": digest,
        "limitations": ["Synthetic and labelled by the same author; not independently adjudicated", "Related variants are not independent samples", "Not representative of Indian SMS prevalence", "Not used for training or numeric threshold fitting"],
        "cases": rows}
    (HERE / "challenge.json").write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    (ROOT / "android-app/app/src/main/assets/benchmark_suite.json").write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
    print(json.dumps({"cases": len(rows), "semantic_scenarios": len(rows)//2,
        "labels": dict(Counter(r['label'] for r in rows)), "languages": dict(Counter(r['language'] for r in rows)), "sha256": digest}, indent=2))

if __name__ == "__main__": main()
