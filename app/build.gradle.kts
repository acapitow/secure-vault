import java.security.KeyStore
import java.security.MessageDigest

plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.compose)
    alias(libs.plugins.kotlin.serialization)
}

// Clé de signature fournie par la CI (secrets GitHub). Jamais versionnée.
val ciKeystorePath = providers.environmentVariable("SIGNING_KEYSTORE_PATH").orNull

// Empreinte SHA-256 du certificat de la CI, vérifiée au lancement (IntegrityChecker).
// Vide pour un build sans clé stable : la vérification est alors désactivée.
val expectedSigner: String = ciKeystorePath?.let { path ->
    val keyStore = KeyStore.getInstance("PKCS12")
    file(path).inputStream().use {
        keyStore.load(it, providers.environmentVariable("SIGNING_STORE_PASSWORD").get().toCharArray())
    }
    val certificate = keyStore.getCertificate(providers.environmentVariable("SIGNING_KEY_ALIAS").get())
    MessageDigest.getInstance("SHA-256").digest(certificate.encoded).joinToString("") { "%02x".format(it) }
}.orEmpty()

android {
    namespace = "io.github.acapitow.vault"
    compileSdk = 37

    defaultConfig {
        applicationId = "io.github.acapitow.vault"
        minSdk = 28
        targetSdk = 37
        versionCode = 4
        versionName = "0.2.2"
        buildConfigField("String", "EXPECTED_SIGNER", "\"$expectedSigner\"")
    }

    signingConfigs {
        if (ciKeystorePath != null) {
            create("ci") {
                storeFile = file(ciKeystorePath)
                storeType = "pkcs12"
                storePassword = providers.environmentVariable("SIGNING_STORE_PASSWORD").get()
                keyAlias = providers.environmentVariable("SIGNING_KEY_ALIAS").get()
                keyPassword = providers.environmentVariable("SIGNING_KEY_PASSWORD").get()
            }
        }
    }

    buildTypes {
        debug {
            // android:debuggable est piloté ici, jamais dans le manifest (MASVS-RESILIENCE).
            isDebuggable = true
            applicationIdSuffix = ".debug"
            versionNameSuffix = "-debug"
            signingConfigs.findByName("ci")?.let { signingConfig = it }
        }
        release {
            isDebuggable = false
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro",
            )
            signingConfig = signingConfigs.findByName("ci") ?: signingConfigs.getByName("debug")
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    buildFeatures {
        compose = true
        buildConfig = true
    }

    packaging {
        resources {
            excludes += setOf(
                "/META-INF/{AL2.0,LGPL2.1}",
                "/META-INF/versions/9/OSGI-INF/MANIFEST.MF",
            )
        }
    }

    testOptions {
        unitTests.isReturnDefaultValues = true
    }
}

dependencies {
    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.activity.compose)
    implementation(libs.androidx.lifecycle.viewmodel.compose)
    implementation(libs.androidx.lifecycle.runtime.compose)
    implementation(libs.androidx.lifecycle.process)
    implementation(libs.androidx.biometric)
    implementation(libs.androidx.fragment) // force une version récente (voir libs.versions.toml)
    implementation(platform(libs.compose.bom))
    implementation(libs.compose.ui)
    implementation(libs.compose.ui.tooling.preview)
    implementation(libs.compose.material3)
    implementation(libs.compose.material.icons.core)
    implementation(libs.kotlinx.serialization.json)
    implementation(libs.kotlinx.coroutines.android)
    implementation(libs.bouncycastle.prov)
    // Lecture des QR codes TOTP : CameraX + ZXing core (Java pur, sans réseau ni Play Services).
    implementation(libs.camera.camera2)
    implementation(libs.camera.lifecycle)
    implementation(libs.camera.view)
    implementation(libs.zxing.core)
    debugImplementation(libs.compose.ui.tooling)

    testImplementation(libs.junit)
    testImplementation(libs.kotlinx.coroutines.test)
}
