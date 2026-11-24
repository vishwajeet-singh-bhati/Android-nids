plugins {
    id("org.jetbrains.kotlin.jvm")
    application
}
application { mainClass.set("nids.core.GoldenCheck") }   // gradle :core:run --args="../golden"
tasks.register<JavaExec>("alignedCheck") {
    classpath = sourceSets["main"].runtimeClasspath
    mainClass.set("nids.core.AlignedCheck")
}
tasks.register<JavaExec>("alignedV2PolicyCheck") {
    classpath = sourceSets["main"].runtimeClasspath
    mainClass.set("nids.core.AlignedV2PolicyCheck")
}

tasks.register<JavaExec>("rejectedHandshakeEvidenceCheck") {
    classpath = sourceSets["main"].runtimeClasspath
    mainClass.set("nids.core.RejectedHandshakeEvidenceCheck")
}
tasks.register<JavaExec>("captureDeliveryClockCheck") {
    classpath = sourceSets["main"].runtimeClasspath
    mainClass.set("nids.core.CaptureDeliveryClockCheck")
}
java { sourceCompatibility = JavaVersion.VERSION_17; targetCompatibility = JavaVersion.VERSION_17 }
kotlin { compilerOptions { jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17) } }

tasks.register<JavaExec>("shortFlowGolden") {
    classpath = sourceSets["main"].runtimeClasspath
    mainClass.set("nids.core.ShortFlowGolden")
    args(rootProject.file("../validation/shortflow_golden").absolutePath)
}

tasks.register<JavaExec>("behaviorGolden") {
    classpath = sourceSets["main"].runtimeClasspath
    mainClass.set("nids.core.BehaviorGolden")
    args(rootProject.file("../validation/behavior_golden").absolutePath)
}

tasks.register<JavaExec>("behaviorTimelineCheck") {
    classpath = sourceSets["main"].runtimeClasspath
    mainClass.set("nids.core.BehaviorTimelineCheck")
}

tasks.register<JavaExec>("tsanetCheck") {
    classpath = sourceSets["main"].runtimeClasspath
    mainClass.set("nids.core.TsanetCheck")
}

tasks.register<JavaExec>("cascadeGolden") {
    classpath = sourceSets["main"].runtimeClasspath
    mainClass.set("nids.core.CascadeGolden")
    args(rootProject.file("../validation/private/cascade_v6_golden.tsv").absolutePath,
         rootProject.file("../validation/reports/cascade_v6/android_feature_parity.json").absolutePath)
}
