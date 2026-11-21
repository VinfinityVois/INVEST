val bootBomVersion = "3.2.0"
dependencies {
    implementation(platform("org.springframework.boot:spring-boot-dependencies:$bootBomVersion"))
    implementation("org.apache.commons:commons-lang3")
    implementation("com.fasterxml.jackson.core:jackson-databind")
    implementation("com.google.code.gson:gson")
}
