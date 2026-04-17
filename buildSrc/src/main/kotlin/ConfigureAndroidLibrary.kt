import com.android.build.api.dsl.KotlinMultiplatformAndroidLibraryTarget
import org.jetbrains.kotlin.gradle.dsl.JvmTarget

fun KotlinMultiplatformAndroidLibraryTarget.configureAndroidLibrary() {
	// Migration guide https://developer.android.com/kotlin/multiplatform/plugin#moving-sources
	compileSdk = 34
	minSdk = 26
	lint {
		checkReleaseBuilds = false
		abortOnError = false
	}
	namespace = "com.icure.kryptom"
	compilerOptions {
		jvmTarget.set(JvmTarget.JVM_1_8) // Keep java 8 for main compilation, needed to support older devices
	}
	compilations.all {
		if (name == "hostTest") {
			compileTaskProvider.configure {
				compilerOptions.jvmTarget.set(JvmTarget.JVM_11) // Need 11 to launch tests, due to kotest version
				
			}
		}
	}
	withHostTest {

	}
}