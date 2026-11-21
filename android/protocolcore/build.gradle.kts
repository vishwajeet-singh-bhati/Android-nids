plugins { `java-library`; application }
java { sourceCompatibility=JavaVersion.VERSION_17;targetCompatibility=JavaVersion.VERSION_17 }
repositories { }
dependencies {
    implementation("org.apache.sshd:sshd-core:2.20.1")
    runtimeOnly("org.slf4j:slf4j-nop:2.0.17")
}
application { mainClass.set("nids.lab.ProtocolClient") }
tasks.register<JavaExec>("protocolSmoke") {
    classpath=sourceSets["main"].runtimeClasspath
    mainClass.set("nids.lab.ProtocolSmoke")
}
