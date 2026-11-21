class RepairController(private val reader: RepairReader) {
    fun lookup(@RequestParam ticketCode: String) = reader.load(ticketCode)
}
class RepairReader(private val jdbc: JdbcTemplate) {
    fun load(code: String): List<String> {
        val sql = "SELECT ticket_code FROM repair_ticket WHERE ticket_code = '$code'"
        return jdbc.queryForList(sql, String::class.java)
    }
}
