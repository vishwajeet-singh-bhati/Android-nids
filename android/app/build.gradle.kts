plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}
android {
    namespace = "nids.app"
    compileSdk = 34
    defaultConfig {
        applicationId = "nids.app"
        minSdk = 26
        targetSdk = 34
        versionCode = 36
        versionName = "0.12.2-aligned-v2-test"
        testInstrumentationRunner = "nids.app.ValidationInstrumentation"
    }
    androidResources { noCompress += listOf("tflite", "pte") }
    compileOptions { sourceCompatibility = JavaVersion.VERSION_17; targetCompatibility = JavaVersion.VERSION_17 }
    kotlinOptions { jvmTarget = "17" }
    buildTypes { release { isMinifyEnabled = false } }
}
dependencies {
    implementation(project(":core"))
    implementation("org.pytorch:executorch-android:1.5.1")
    implementation("com.google.ai.edge.litert:litert:1.4.0")
}
