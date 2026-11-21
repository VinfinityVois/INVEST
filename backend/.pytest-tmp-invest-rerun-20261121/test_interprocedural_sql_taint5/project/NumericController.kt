class NumericController(private val service: NumericService) {
    fun lookup(@RequestParam rawId: String) = service.find(rawId.toLong())
}
class NumericService(private val jdbc: JdbcTemplate) {
    fun find(id: Long): List<String> =
        jdbc.queryForList("SELECT name FROM item WHERE id = $id", String::class.java)
}
