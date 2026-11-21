val archiveFormatVersion = "1.25.0"
val manifestVersion = providers.gradleProperty("legacyManifestJsonVersion").get()
dependencies {
    implementation("org.apache.commons:commons-text:1.9")
    implementation("org.jsoup:jsoup:1.14.1")
    implementation("org.apache.commons:commons-compress:$archiveFormatVersion")
    add(
        "implementation",
        "commons-net:commons-net:3.8.0",
    )
    implementation("org.json:json:$manifestVersion")
    implementation("org.apache.commons:commons-lang3:3.20.0")
}
