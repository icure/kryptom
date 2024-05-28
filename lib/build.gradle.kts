import com.vanniktech.maven.publish.SonatypeHost
import org.jetbrains.kotlin.gradle.ExperimentalKotlinGradlePluginApi

plugins {
	kotlinMultiplatform()
	kotestMultiplatform()
	androidLibrary()
	id("maven-publish")
	signing
	id("com.vanniktech.maven.publish") version "0.28.0"
}

group = "com.icure.kryptom"

val repoUsername: String by project
val repoPassword: String by project
val mavenReleasesRepository: String by project

project.version = "1.0.1"

@OptIn(ExperimentalKotlinGradlePluginApi::class)
kotlin {
	configureMultiplatform(this, "Kryptom")

	compilerOptions {
		freeCompilerArgs.add("-Xexpect-actual-classes")
	}

	sourceSets {
		val commonMain by getting {
			dependencies {
				implementation(libs.ktorUtils)
			}
		}
		val commonTest by getting {
			dependencies {
				implementation(libs.kotestAssertions)
				implementation(libs.kotestEngine)
				implementation(libs.kotestDatatest)
				implementation(kotlin("test-common"))
				implementation(kotlin("test-annotations-common"))
			}
		}
		val jvmMain by getting {
			dependencies {
				implementation(libs.bouncyCastle)
			}
		}
		val jvmTest by getting {
			dependencies {
				implementation(libs.kotestRunnerJunit)
			}
		}
		val jsMain by getting {
			languageSettings {
				optIn("kotlin.js.ExperimentalJsExport")
			}
			dependencies {
			}
		}
		val androidMain by getting {
			dependencies {
				implementation(libs.bouncyCastle)
			}
		}
		val androidUnitTest by getting {
			dependencies {
				implementation(libs.kotestRunnerJunit)
			}
		}
		optInIos("kotlinx.cinterop.ExperimentalForeignApi", "kotlinx.cinterop.BetaInteropApi")
	}
}

android {
	namespace = "com.icure.kryptom"
	configureAndroidLibrary()
}

configureJvmTest()

fun projectHasSignatureProperties() =
	project.hasProperty("signing.keyId") && project.hasProperty("signing.secretKeyRingFile") && project.hasProperty("signing.password")

if (projectHasSignatureProperties()) {
	signing {
		useInMemoryPgpKeys(
			file(project.property("signing.secretKeyRingFile") as String).readText(),
			project.property("signing.password") as String
		)
		sign(publishing.publications)
	}
}

mavenPublishing {
	coordinates(group as String, rootProject.name, project.version as String)

	pom {
		name.set("Kryptom")
		description.set("""
			Provides access from kotlin multiplatform to:

			- Native cryptographic primitives and digest algorithms including:
				- Secure random
				- Aes encryption
				- Rsa encryption and signing
				- Hmac signing
			- Byte array encoding and decoding (hex, base64)
		""".trimIndent())
		url.set("https://github.com/icure/kryptom")

		licenses {
			license {
				name.set("MIT License")
				url.set("https://choosealicense.com/licenses/mit/")
				distribution.set("https://choosealicense.com/licenses/mit/")
			}
		}
		developers {
			developer {
				id.set("icure")
				name.set("iCure")
				url.set("https://github.com/iCure/")
			}
		}
		scm {
			url.set("https://github.com/icure/kryptom")
			connection.set("scm:git:git://github.com/icure/kryptom.git")
			developerConnection.set("scm:git:ssh://git@github.com:icure/kryptom.git")
		}
	}

	publishToMavenCentral(SonatypeHost.CENTRAL_PORTAL, automaticRelease = true)

	if (projectHasSignatureProperties()) {
		signAllPublications()
	}
}

rootProject.plugins.withType(org.jetbrains.kotlin.gradle.targets.js.nodejs.NodeJsRootPlugin::class.java) {
	rootProject.the<org.jetbrains.kotlin.gradle.targets.js.nodejs.NodeJsRootExtension>().nodeVersion = "20.13.1"
}

// Configure all publishing tasks
if (!projectHasSignatureProperties()) {
	tasks.withType<PublishToMavenRepository> {
		doFirst {
			throw IllegalStateException("Cannot publish to Maven Central without signing properties")
		}
	}
}
