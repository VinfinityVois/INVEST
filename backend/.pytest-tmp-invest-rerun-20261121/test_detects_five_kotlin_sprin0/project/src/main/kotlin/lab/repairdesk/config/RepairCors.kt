class RepairCors {
    fun corsConfigurationSource() {
        val customerSummary = CorsConfiguration().apply {
            allowedOriginPatterns = listOf("*")
            allowCredentials = true
            allowedMethods = listOf("GET")
        }
        source.registerCorsConfiguration("/api/customer/summary", customerSummary)
    }
}
