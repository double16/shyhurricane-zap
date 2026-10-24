plugins {
    id("org.zaproxy.add-on") version "0.13.1"
    id("com.diffplug.spotless") version "8.10.4"
    id("io.github.ben-manes.versions") version "0.66.0"
    java
    jacoco
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
    testImplementation("org.mockito:mockito-core:5.20.0")
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

spotless {
    // Adopt formatting incrementally without rewriting unrelated existing code.
    ratchetFrom("HEAD")
    java {
        target("src/**/*.java")
        googleJavaFormat("1.24.0").aosp()
        removeUnusedImports()
    }
}

jacoco {
    toolVersion = "0.8.15"
}

val forwardingClasses = listOf(
    "com/github/double16/ExtensionShyHurricaneForwarder*.class",
    "com/github/double16/ForwardingPayloads*.class",
    "com/github/double16/ShyHurricaneClient*.class",
    "com/github/double16/ManualSendService*.class",
    "com/github/double16/ShyHurricaneMenus*.class"
)

tasks.jacocoTestReport {
    dependsOn(tasks.test)
    reports {
        xml.required.set(true)
        html.required.set(true)
    }
}

tasks.jacocoTestCoverageVerification {
    dependsOn(tasks.test)
    classDirectories.setFrom(sourceSets.main.get().output.asFileTree.matching {
        forwardingClasses.forEach { include(it) }
    })
    violationRules {
        rule {
            element = "SOURCEFILE"
            limit {
                counter = "LINE"
                minimum = "0.80".toBigDecimal()
            }
            limit {
                counter = "BRANCH"
                minimum = "0.80".toBigDecimal()
            }
        }
    }
}

tasks.check {
    dependsOn(tasks.jacocoTestReport, tasks.jacocoTestCoverageVerification)
}
