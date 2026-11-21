dependencyResolutionManagement {
  versionCatalogs {
    create("quality") { from(files("gradle/quality.versions.toml")) }
  }
}
