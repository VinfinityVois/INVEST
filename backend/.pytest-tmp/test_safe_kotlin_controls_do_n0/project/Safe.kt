class Safe {
    fun query(@RequestParam ticketCode: String) =
        jdbc.queryForList("SELECT ticket_code FROM repair_ticket WHERE ticket_code = ?", String::class.java, ticketCode)
    fun tls() { connection.connect() }
    fun publicCatalog() { rules.requestMatchers(GET, "/api/catalog/services").permitAll() }
}
