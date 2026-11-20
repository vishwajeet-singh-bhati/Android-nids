plugins { id("org.jetbrains.kotlin.jvm") }
dependencies { implementation(files("../../runs/phone_alignment_v2/extractor/core.jar")) }
java { sourceCompatibility = JavaVersion.VERSION_17; targetCompatibility = JavaVersion.VERSION_17 }
kotlin { compilerOptions { jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17) } }
