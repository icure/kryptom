import org.gradle.kotlin.dsl.`kotlin-dsl`

plugins {
	`kotlin-dsl`
}

repositories {
	mavenCentral()
	gradlePluginPortal()
	google()
}

dependencies {
	implementation(libs.kotlinMultiplatformPlugin)
	implementation(libs.kotestPlugin)
	implementation(libs.kspPlugin)
	implementation(libs.androidLibraryPlugin)
}
