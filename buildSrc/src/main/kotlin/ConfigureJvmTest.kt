import org.gradle.api.tasks.testing.Test
import org.gradle.kotlin.dsl.named
import org.gradle.kotlin.dsl.withType
import org.gradle.api.Project

fun Project.configureJvmTest() {
	tasks.named<Test>("jvmTest") {
		doConfigureJvmTest()
	}
	tasks.withType<Test>().matching { it.name.contains("HostTest") }.configureEach {
		doConfigureJvmTest()
	}
}

private fun Test.doConfigureJvmTest() {
	useJUnitPlatform()
	filter {
		isFailOnNoMatchingTests = false
	}
	testLogging {
		showExceptions = true
		showStandardStreams = true
		events = setOf(
			org.gradle.api.tasks.testing.logging.TestLogEvent.FAILED,
			org.gradle.api.tasks.testing.logging.TestLogEvent.PASSED
		)
		exceptionFormat = org.gradle.api.tasks.testing.logging.TestExceptionFormat.FULL
	}
}
