plugins {
    id("org.zaproxy.add-on") version "0.13.1"
    id("com.diffplug.spotless") version "7.2.1"
    id("com.github.ben-manes.versions") version "0.52.0"
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
    compileOnly("org.zaproxy:zap:2.16.1")
    implementation(platform("com.fasterxml.jackson:jackson-bom:2.19.+" ))
    implementation("com.fasterxml.jackson.core:jackson-databind")
}

zapAddOn {
    addOnName.set("ShyHurricane Forwarder")
    zapVersion.set("2.16.0")
    manifest {
        author.set("Patrick Double <github.com/double16>")
    }
}
