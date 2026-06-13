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
    compileOnly("org.zaproxy:zap:2.16.1")
    implementation(platform("com.fasterxml.jackson:jackson-bom:2.22.+" ))
    implementation("com.fasterxml.jackson.core:jackson-databind")
}

zapAddOn {
    addOnName.set("ShyHurricane")
    zapVersion.set("2.16.0")
    manifest {
        author.set("Patrick Double <github.com/double16>")
    }
}
