package sample.service
class SearchService(private val jdbc: JdbcTemplate) {
    fun find(value: String): List<String> {
        val sql = "SELECT name FROM item WHERE name = '$value'"
        return jdbc.queryForList(sql, String::class.java)
    }
}
