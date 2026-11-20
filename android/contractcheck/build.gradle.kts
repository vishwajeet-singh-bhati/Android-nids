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
