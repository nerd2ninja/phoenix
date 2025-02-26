import org.jetbrains.kotlin.gradle.plugin.mpp.KotlinNativeTarget
import org.jetbrains.kotlin.gradle.plugin.mpp.Framework

plugins {
    kotlin("multiplatform")
    id("kotlinx-serialization")
    id("com.squareup.sqldelight")
    if (System.getProperty("includeAndroid")?.toBoolean() == true) {
        id("com.android.library")
    }
}

val includeAndroid = System.getProperty("includeAndroid")?.toBoolean() ?: false

kotlin {
    if (includeAndroid) {
        android {
            compilations.all {
                kotlinOptions.jvmTarget = "1.8"
            }
        }
    }

    listOf(iosX64(), iosArm64(), iosSimulatorArm64()).forEach {
        it.binaries {
            framework {
                baseName = "PhoenixShared"
                embedBitcode = Framework.BitcodeEmbeddingMode.DISABLE
            }
            configureEach {
                it.compilations.all {
                    kotlinOptions.freeCompilerArgs += "-Xoverride-konan-properties=osVersionMin.ios_x64=14.0;osVersionMin.ios_arm64=14.0"
                    kotlinOptions.freeCompilerArgs += listOf("-linker-options", "-application_extension")
                }
            }
        }
    }

    sourceSets {
        // -- common sources
        val commonMain by getting {
            dependencies {
                // lightning-kmp
                api("fr.acinq.lightning:lightning-kmp:${Versions.lightningKmp}")
                // ktor
                implementation("io.ktor:ktor-client-core:${Versions.ktor}")
                implementation("io.ktor:ktor-client-json:${Versions.ktor}")
                implementation("io.ktor:ktor-serialization-kotlinx-json:${Versions.ktor}")
                implementation("io.ktor:ktor-client-content-negotiation:${Versions.ktor}")
                // sqldelight
                implementation("com.squareup.sqldelight:runtime:${Versions.sqlDelight}")
                implementation("com.squareup.sqldelight:coroutines-extensions:${Versions.sqlDelight}")
                // file system
                api("org.kodein.memory:kodein-memory-files:${Versions.kodeinMemory}")
            }
        }

        val commonTest by getting {
            dependencies {
                implementation(kotlin("test-common"))
                implementation(kotlin("test-annotations-common"))
                implementation("io.ktor:ktor-client-mock:${Versions.ktor}")
            }
        }

        // -- android sources
        if (includeAndroid) {
            val androidMain by getting {
                dependencies {
                    implementation("androidx.core:core-ktx:${Versions.Android.ktx}")
                    implementation("fr.acinq.secp256k1:secp256k1-kmp-jni-android:${Versions.secp256k1}")
                    implementation("io.ktor:ktor-network:${Versions.ktor}")
                    implementation("io.ktor:ktor-network-tls:${Versions.ktor}")
                    implementation("io.ktor:ktor-client-android:${Versions.ktor}")
                    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:${Versions.coroutines}")
                    implementation("com.squareup.sqldelight:android-driver:${Versions.sqlDelight}")
                }
            }
            val androidTest by getting {
                dependencies {
                    implementation(kotlin("test-junit"))
                    implementation("androidx.test.ext:junit:1.1.3")
                    implementation("androidx.test.espresso:espresso-core:3.4.0")
                    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-test:${Versions.coroutines}")
                    val currentOs = org.gradle.internal.os.OperatingSystem.current()
                    val target = when {
                        currentOs.isLinux -> "linux"
                        currentOs.isMacOsX -> "darwin"
                        currentOs.isWindows -> "mingw"
                        else -> error("Unsupported OS $currentOs")
                    }
                    implementation("fr.acinq.secp256k1:secp256k1-kmp-jni-jvm-$target:${Versions.secp256k1}")
                    implementation("com.squareup.sqldelight:sqlite-driver:${Versions.sqlDelight}")
                }
            }
        }

        // -- ios sources
        val iosX64Main by getting
        val iosArm64Main by getting
        val iosSimulatorArm64Main by getting
        val iosMain by creating {
            dependsOn(commonMain)
            dependencies {
                implementation("io.ktor:ktor-client-ios:${Versions.ktor}")
                implementation("com.squareup.sqldelight:native-driver:${Versions.sqlDelight}")
            }
            iosX64Main.dependsOn(this)
            iosArm64Main.dependsOn(this)
            iosSimulatorArm64Main.dependsOn(this)
        }

        val iosX64Test by getting
        val iosArm64Test by getting
        val iosSimulatorArm64Test by getting
        val iosTest by creating {
            dependsOn(commonTest)
            dependencies {
                implementation("com.squareup.sqldelight:native-driver:${Versions.sqlDelight}")
            }
            iosX64Test.dependsOn(this)
            iosArm64Test.dependsOn(this)
            iosSimulatorArm64Test.dependsOn(this)
        }

        all {
            languageSettings.optIn("kotlin.RequiresOptIn")
        }
    }
}

sqldelight {
    database("ChannelsDatabase") {
        packageName = "fr.acinq.phoenix.db"
        sourceFolders = listOf("channelsdb")
    }
    database("PaymentsDatabase") {
        packageName = "fr.acinq.phoenix.db"
        sourceFolders = listOf("paymentsdb")
    }
    database("AppDatabase") {
        packageName = "fr.acinq.phoenix.db"
        sourceFolders = listOf("appdb")
    }
}

if (includeAndroid) {
    extensions.configure<com.android.build.gradle.LibraryExtension>("android") {
        namespace = "fr.acinq.phoenix.shared"
        compileSdk = 32
        defaultConfig {
            minSdk = 24
            targetSdk = 32
            testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        }

        compileOptions {
            sourceCompatibility = JavaVersion.VERSION_1_8
            targetCompatibility = JavaVersion.VERSION_1_8
        }

        testOptions {
            unitTests.isReturnDefaultValues = true
        }

        sourceSets["main"].manifest.srcFile("src/androidMain/AndroidManifest.xml")
    }
}
