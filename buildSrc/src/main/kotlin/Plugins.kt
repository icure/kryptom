import org.gradle.kotlin.dsl.PluginDependenciesSpecScope

fun PluginDependenciesSpecScope.kotlinMultiplatform(apply: Boolean = true) {
	id("org.jetbrains.kotlin.multiplatform").apply(apply)
}

fun PluginDependenciesSpecScope.kotest(apply: Boolean = true) {
	id("io.kotest").apply(apply)
}

fun PluginDependenciesSpecScope.androidLibrary(apply: Boolean = true) {
	id("com.android.library").apply(apply)
}

fun PluginDependenciesSpecScope.ksp(apply: Boolean = true) {
	id("com.google.devtools.ksp").apply(apply)
}
