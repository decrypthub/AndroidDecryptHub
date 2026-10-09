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
        versionCode = 9
        versionName = "0.3.10"
        buildConfigField(
            "String",
            "MANAGER_CERT_SHA256",
            "\"${providers.gradleProperty("adhManagerCertSha256").orElse("").get()}\"",
        )
    }

    buildFeatures {
        buildConfig = true
    }

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
}
