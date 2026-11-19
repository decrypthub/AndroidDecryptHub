plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.android)
}

android {
    namespace = "com.adh.daemon"
    compileSdk = 36

    defaultConfig {
        applicationId = "com.adh.daemon"
        minSdk = 26
        targetSdk = 34
        versionCode = 18
        versionName = "1.0.0"
        buildConfigField(
            "String",
            "MANAGER_CERT_SHA256",
            "\"${providers.gradleProperty("adhManagerCertSha256").orElse("").get()}\"",
        )
    }

    buildFeatures {
        buildConfig = true
    }
    if(providers.gradleProperty("adhP5Sandbox").orNull=="true") sourceSets["debug"].java.srcDir("src/p5Fixture/java")

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = "17"
    }
}

dependencies {
    implementation(project(":core"))
    testImplementation(libs.junit)
    testImplementation(libs.org.json)
}

// Explicit host-only interoperability fixture. No APK install, app_process or device command.
tasks.register("writeDeviceRpcFixtureClasspath") {
    val unitTest = tasks.named<Test>("testDebugUnitTest").get()
    val runtimeClasspath = unitTest.classpath + unitTest.testClassesDirs
    dependsOn(runtimeClasspath)
    doLast {
        val files = runtimeClasspath.files.map { it.absolutePath }
        val output = layout.buildDirectory.file("device-rpc-fixture-classpath.json").get().asFile
        output.parentFile.mkdirs()
        output.writeText(files.joinToString(",", "[", "]") { "\"" + it.replace("\\", "\\\\").replace("\"", "\\\"") + "\"" })
    }
}
