plugins {
    id("com.android.application")
}

// Optional LSPosed/Xposed backend: a THIN loader APK. It has no activity, no AndroidX and no
// analysis code — it only brings libadh_agent.so into a scoped target process and lets the
// agent talk to the Host ADH Daemon like every other injection path.
android {
    namespace = "com.adh.xposed"
    compileSdk = 36

    defaultConfig {
        applicationId = "com.adh.xposed"
        minSdk = 26
        targetSdk = 34
        versionCode = 1
        versionName = "0.1.0"

        ndk {
            abiFilters += "arm64-v8a"
        }
    }

    buildTypes {
        debug {
            isDebuggable = true
        }
        release {
            isMinifyEnabled = false
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    // Keep the bundled agent .so UNCOMPRESSED inside the APK, because that is the layout the
    // framework's module classloader points at:
    //   nativeLibraryDirectories=[/data/app/~~xx/com.adh.xposed-yy/base.apk!/lib/arm64-v8a, ...]
    // (verified on device — an extract-on-install layout makes System.loadLibrary miss the .so).
    // AdhXposedEntry still keeps an absolute-path fallback for extracted layouts.
    packaging {
        jniLibs {
            useLegacyPackaging = false
        }
    }

    lint {
        abortOnError = false
    }
}

dependencies {
    // Compile-only: de.robv.android.xposed.* come from the framework at runtime (never packaged).
    compileOnly(project(":api-stub"))
}