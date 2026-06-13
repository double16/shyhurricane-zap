plugins {
    id("org.zaproxy.add-on") version "0.13.1"
    id("com.diffplug.spotless") version "8.6.0"
    id("com.github.ben-manes.versions") version "0.54.0"
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

    testImplementation("org.junit.jupiter:junit-jupiter:5.10.2")
    testImplementation("commons-configuration:commons-configuration:1.10")
    testImplementation("org.zaproxy:zap:2.17.0")
}

zapAddOn {
    addOnName.set("ShyHurricane")
    zapVersion.set("2.16.0")
    manifest {
        author.set("Patrick Double <github.com/double16>")
    }
}

tasks.test {
    useJUnitPlatform()
}
