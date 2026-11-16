plugins { alias(libs.plugins.android.application) }
android {
    namespace="com.adh.p5sandbox";compileSdk=36;ndkVersion="28.2.13676358"
    defaultConfig {
        applicationId="com.adh.p5sandbox";minSdk=26;targetSdk=28
        versionCode=providers.gradleProperty("adhP5SandboxVersion").orElse("1").get().toInt();versionName="p5-fixture"
        ndk { abiFilters += "arm64-v8a" }
        externalNativeBuild { cmake { arguments += "-DANDROID_STL=c++_static" } }
    }
    externalNativeBuild { cmake { path=file("src/main/cpp/CMakeLists.txt");version="3.22.1" } }
    buildTypes { debug { isDebuggable=true } }
    sourceSets["main"].jniLibs.srcDir("src/main/jniLibs")
    compileOptions { sourceCompatibility=JavaVersion.VERSION_17;targetCompatibility=JavaVersion.VERSION_17 }
}
