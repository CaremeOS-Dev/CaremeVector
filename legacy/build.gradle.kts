plugins { alias(libs.plugins.agp.lib) }

android {
    namespace = "org.matrix.vector.legacy"

    androidResources { enable = false }

    defaultConfig { consumerProguardFiles("consumer-rules.pro") }

    // CAREME: a minimal compile jar carrying the resource-area framework classes with their hidden
    // members (Resources(ClassLoader), TypedArray(Resources), ...) overlaid from an android-27
    // hidden-API build. CaremeOS ART 8.1 cannot define a class whose static superclass lives in a
    // separate in-memory/file dex, so the upstream runtime-generated xposed.dummy superclass cannot
    // be linked here; XResources instead extends android.content.res.Resources/TypedArray directly.
    // Prepended so these classes win over the public compileSdk android.jar; everything else still
    // resolves from the full compileSdk jar (it supplies the newer VERSION_CODES this jar lacks).
    val resJar = rootProject.layout.projectDirectory.file("libs/android-res-min.jar")
    dependencies.add("compileOnly", files(resJar))
    tasks.withType(JavaCompile::class.java).configureEach {
        doFirst {
            classpath = files(resJar) + classpath
        }
    }
}

dependencies {
    api(projects.xposed)
    implementation(projects.external.apache)
    implementation(projects.hiddenapi.bridge)
    implementation(projects.services.daemonService)
    compileOnly(libs.androidx.annotation)
    compileOnly(projects.hiddenapi.stubs)
}
