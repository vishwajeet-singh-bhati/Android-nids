package com.bharat.smsguard.tier1

import java.io.File

fun runCascadeChecks(args: Array<String>) {
    val detector = Tier1Detector(PortableLinearModel.fromJson(File(args[0]).readText()), RiskPolicy.production())
    val hamScores = mapOf("ham" to 0.98, "spam" to 0.01, "smishing" to 0.01)
    val scamScores = mapOf("ham" to 0.01, "spam" to 0.01, "smishing" to 0.98)
    val money = detector.predict("double your money in 2 days")
    for (text in listOf("hi", "hello", "hii!", "namaste", "नमस्ते", "good morning")) {
        val greeting = detector.predict(text)
        check(RoutineMessages.reason(greeting) == "greeting")
        check(!CascadePolicy.shouldRoute(greeting))
        check(RoutineMessages.apply(greeting, "greeting").riskLevel == "low")
    }
    for (text in listOf("Send OTP now", "hi send your OTP", "hello pay Rs 100 now at https://example.invalid", "pay now")) {
        check(RoutineMessages.reason(detector.predict(text)) == null)
    }
    check(CascadePolicy.shouldRoute(money))
    val moneyResult = CascadePolicy.fuse(money, hamScores)
    check(moneyResult.riskLevel == "suspicious")
    check(moneyResult.assessment.reasonCodes.contains("UNREALISTIC_RETURN_PROMISE"))
    check(AlertPolicy.attentionRequired(AlertPolicy.preliminary(money)))
    check(AlertPolicy.financialRisk(moneyResult))
    check(AlertPolicy.attentionRequired(moneyResult))
    val sale = detector.predict("Sale ends today! Get 50% off shoes. Shop at https://example.invalid/sale")
    check(CascadePolicy.fuse(sale, scamScores).riskLevel == "low")
    check(!AlertPolicy.attentionRequired(CascadePolicy.fuse(sale, scamScores)))
    val kyc = detector.predict("Your KYC is expiring today. Click http://example.invalid/kyc and share OTP 482913 to avoid account block.")
    check(CascadePolicy.fuse(kyc, hamScores).riskLevel == "high")
    val otp = detector.predict("Your OTP is 123456. Do not share it with anyone.")
    val spamScores = mapOf("ham" to 0.01, "spam" to 0.98, "smishing" to 0.01)
    check(CascadePolicy.fuse(otp, spamScores).label == "ham")
    check(CascadePolicy.fuse(otp, spamScores).riskLevel == "low")
    check(!AlertPolicy.financialRisk(CascadePolicy.fuse(otp, spamScores)))
    check(!CascadePolicy.returnPromise("Beware of offers to double your money in 2 days"))
    check(!CascadePolicy.returnPromise("Double your money in 20 years"))
    check(!CascadePolicy.returnPromise("Your loan EMI is due in 2 days"))
    check(CascadePolicy.returnPromise("Triple your capital within three days"))
    check(CascadePolicy.returnPromise("This is not a scam: double your money in 2 days"))
    val transaction = detector.predict("Your payment was successful.")
    if (transaction.evidence.flags[Codes.BENIGN_TRANSACTIONAL] == true) check(!CascadePolicy.shouldRoute(transaction))
    println("Cascade checks passed: routing, neural disagreement, ordinary promotion, explicit evidence, return-promise controls")
}
