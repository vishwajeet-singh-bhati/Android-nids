package com.bharat.smsguard.tier1

import kotlin.system.exitProcess

fun main(args: Array<String>) {
    when (args.firstOrNull()) {
        "--batch" -> runCascadeBatch(args.drop(1).toTypedArray())
        "--cascade" -> runCascadeChecks(args.drop(1).toTypedArray())
        "--model" -> {
            if (args.size < 3) {
                System.err.println("usage: tier1-parity --model <portable_model.json> <fixture.tsv>")
                error("SMS parity arguments failed")
            }
            runModelParity(args.drop(1).toTypedArray())
        }
        "--flags" -> {
            if (args.size < 2) {
                System.err.println("usage: tier1-parity --flags <fixture.tsv>")
                error("SMS parity arguments failed")
            }
            runFlagParity(args.drop(1).toTypedArray())
        }
        "--policy" -> {
            if (args.size < 3) {
                System.err.println("usage: tier1-parity --policy <portable_model.json> <fixture.tsv>")
                error("SMS parity arguments failed")
            }
            runPolicyParity(args.drop(1).toTypedArray())
        }
        else -> runTier1Parity(args)
    }
}
