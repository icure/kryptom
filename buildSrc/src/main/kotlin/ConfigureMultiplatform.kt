
import org.gradle.api.NamedDomainObjectContainer
import org.gradle.kotlin.dsl.get
import org.jetbrains.kotlin.gradle.plugin.KotlinSourceSet

fun NamedDomainObjectContainer<KotlinSourceSet>.optInApple(vararg optIns: String) {
	listOf(
		get("appleMain"),
		get("iosMain"),
		get("macosMain"),
		get("iosArm64Main"),
		get("iosX64Main"),
		get("iosSimulatorArm64Main"),
		get("macosArm64Main"),
		get("macosX64Main"),
	).forEach { sourceSet ->
		optIns.forEach { optIn ->
			sourceSet.languageSettings.optIn(optIn)
		}
	}
}
