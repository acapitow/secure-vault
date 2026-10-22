buildscript {
    dependencies {
        // AGP 9 embarque KGP 2.2.10 ; on force la version de Kotlin du catalogue
        // pour qu'elle corresponde au plugin du compilateur Compose.
        classpath(libs.kotlin.gradle.plugin)
    }
}

plugins {
    alias(libs.plugins.android.application) apply false
    alias(libs.plugins.kotlin.compose) apply false
    alias(libs.plugins.kotlin.serialization) apply false
}
