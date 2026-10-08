plugins {
    id("org.zaproxy.add-on") version "0.13.1"
    id("com.diffplug.spotless") version "8.10.3"
    id("io.github.ben-manes.versions") version "0.65.0"
    java
}

java {
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
}

repositories {
    mavenCentral()
}

dependencies {
    compileOnly("org.zaproxy:zap:2.17.0")
    implementation(platform("com.fasterxml.jackson:jackson-bom:2.22.+" ))
    implementation("com.fasterxml.jackson.core:jackson-databind")

    testImplementation("org.junit.jupiter:junit-jupiter:6.1.3")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher:6.1.3")
    testImplementation("commons-configuration:commons-configuration:1.10")
    testImplementation("org.zaproxy:zap:2.17.0")
}

zapAddOn {
    addOnName.set("ShyHurricane")
    zapVersion.set("2.17.0")
    manifest {
        author.set("Patrick Double <github.com/double16>")
    }
}

tasks.test {
    useJUnitPlatform()
}
