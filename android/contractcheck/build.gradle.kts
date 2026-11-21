import java.security.MessageDigest

plugins { id("com.android.application");id("org.jetbrains.kotlin.android") }
android {
    namespace="nids.contractcheck";compileSdk=34
    defaultConfig { applicationId="nids.contractcheck";minSdk=26;targetSdk=34;versionCode=1;versionName="0.1.0" }
    compileOptions { sourceCompatibility=JavaVersion.VERSION_17;targetCompatibility=JavaVersion.VERSION_17 }
    kotlinOptions { jvmTarget="17" }
}
dependencies { implementation(project(":core")) }
val contractAssets=layout.buildDirectory.dir("generated/contractAssets")
android.sourceSets["main"].assets.srcDir(contractAssets)
val generateContractManifest=tasks.register("generateContractManifest"){
    val sources=fileTree("../core/src/main/kotlin/nids/core"){include("*.kt")}
    inputs.files(sources);outputs.dir(contractAssets)
    doLast{
        val folder=contractAssets.get().asFile;folder.mkdirs()
        val entries=sources.files.sortedBy{it.name}.joinToString(","){file->
            val digest=MessageDigest.getInstance("SHA-256").digest(file.readBytes()).joinToString(""){"%02x".format(it)}
            "\"${file.name}\":\"$digest\""
        }
        folder.resolve("contract_sources.json").writeText("{$entries}\n")
    }
}
tasks.named("preBuild"){dependsOn(generateContractManifest)}

// Execute the exact new app presentation/store code in this separate sandbox
// before building/installing a replacement for the user's monitoring app.
val hybridSources=layout.buildDirectory.dir("generated/hybridSources")
val hybridAssets=layout.buildDirectory.dir("generated/hybridAssets")
android.sourceSets["main"].java.srcDir(hybridSources)
android.sourceSets["main"].assets.srcDir(hybridAssets)
val hybridInputs=listOf("TsanetExplanationFacts.kt","HybridActivityNote.kt","ObservationStore.kt","UidResolver.kt","NetworkObservationPolicy.kt")
val generateHybridSources=tasks.register("generateHybridSources"){
    val production=hybridInputs.map{file("../app/src/main/kotlin/nids/app/$it")}
    val contract=file("../app/src/androidTest/kotlin/nids/app/HybridNoteContract.kt")
    inputs.files(production+contract);outputs.dir(hybridSources);outputs.dir(hybridAssets)
    doLast{
        val folder=hybridSources.get().asFile.resolve("nids/app");folder.mkdirs()
        for(source in production+contract)source.copyTo(folder.resolve(source.name),overwrite=true)
        val hashes=(production+contract).joinToString(","){source->"\"${source.name}\":\""+MessageDigest.getInstance("SHA-256").digest(source.readBytes()).joinToString(""){"%02x".format(it)}+"\""}
        // Old builds shared an output directory with generateContractManifest,
        // allowing a stale assets snapshot. Give this manifest its own output.
        contractAssets.get().asFile.resolve("hybrid_sources.json").delete()
        hybridAssets.get().asFile.apply{mkdirs()}.resolve("hybrid_sources.json").writeText("{$hashes}\n")
    }
}
tasks.named("preBuild"){dependsOn(generateHybridSources)}
