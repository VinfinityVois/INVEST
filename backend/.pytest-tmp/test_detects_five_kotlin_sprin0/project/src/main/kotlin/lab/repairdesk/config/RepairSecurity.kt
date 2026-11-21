class RepairSecurity {
    fun securityFilterChain() {
        rules.requestMatchers(GET, "/api/catalog/services").permitAll()
        rules.requestMatchers(GET, "/api/pickup/export").permitAll()
    }
}
