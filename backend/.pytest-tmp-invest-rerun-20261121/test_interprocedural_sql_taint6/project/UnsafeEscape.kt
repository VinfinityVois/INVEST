class UnsafeEscapeController(private val service: UnsafeEscapeService) {
    fun find(@RequestParam term: String) = service.find(HtmlUtils.htmlEscape(term))
}
class UnsafeEscapeService(private val jdbc: JdbcTemplate) {
    fun find(escaped: String): List<String> {
        val sql = "SELECT name FROM item WHERE name = '$escaped'"
        return jdbc.queryForList(sql, String::class.java)
    }
}
