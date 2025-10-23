plugins {
    id("java")
}

repositories {
    mavenCentral()
}

dependencies {
    val localMontoyaJar = file("libs/montoya-api-2025.11.2.jar")
    if (localMontoyaJar.exists()) {
        compileOnly(files(localMontoyaJar))
    }
    compileOnly("net.portswigger.burp.extensions:montoya-api:2025.6")
    implementation("com.microsoft.playwright:playwright:1.55.0")
}

tasks.withType<JavaCompile> {
    sourceCompatibility = "21"
    targetCompatibility = "21"
    options.encoding = "UTF-8"
}

tasks.jar {
    duplicatesStrategy = DuplicatesStrategy.EXCLUDE
    from(configurations.runtimeClasspath.get().filter { it.isDirectory })
    from(configurations.runtimeClasspath.get().filterNot { it.isDirectory }.map { zipTree(it) })
}