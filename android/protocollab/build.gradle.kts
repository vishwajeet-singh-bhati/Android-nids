plugins { id("com.android.application");id("org.jetbrains.kotlin.android") }
android {
    namespace="nids.protocollab";compileSdk=34
    defaultConfig { applicationId="nids.protocollab";minSdk=26;targetSdk=34;versionCode=1;versionName="0.1.0" }
    compileOptions { sourceCompatibility=JavaVersion.VERSION_17;targetCompatibility=JavaVersion.VERSION_17 }
    kotlinOptions { jvmTarget="17" }
    packaging { resources { excludes += setOf("META-INF/DEPENDENCIES","META-INF/INDEX.LIST");pickFirsts += setOf("META-INF/LICENSE","META-INF/NOTICE") } }
}
dependencies { implementation(project(":protocolcore")) }
