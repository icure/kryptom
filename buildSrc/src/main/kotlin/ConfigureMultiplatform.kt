
import org.gradle.api.NamedDomainObjectContainer
import org.gradle.api.Project
import org.gradle.kotlin.dsl.get
import org.jetbrains.kotlin.gradle.dsl.KotlinMultiplatformExtension
import org.jetbrains.kotlin.gradle.plugin.KotlinSourceSet
import org.jetbrains.kotlin.gradle.plugin.mpp.apple.XCFramework
import java.util.Properties

fun NamedDomainObjectContainer<KotlinSourceSet>.optInIos(vararg optIns: String) {
	listOf(
		get("iosMain"),
		get("iosArm64Main"),
		get("iosX64Main"),
		get("iosSimulatorArm64Main"),
	).forEach { sourceSet ->
		optIns.forEach { optIn ->
			sourceSet.languageSettings.optIn(optIn)
		}
	}
}
