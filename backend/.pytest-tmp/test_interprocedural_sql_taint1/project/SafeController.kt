class SafeController(private val reader: SafeReader) {
    fun lookup(@RequestParam ticketCode: String) = reader.load(ticketCode)
}
class SafeReader(private val jdbc: JdbcTemplate) {
    fun load(code: String): List<String> =
        jdbc.queryForList("SELECT ticket_code FROM repair_ticket WHERE ticket_code = ?", String::class.java, code)
}
