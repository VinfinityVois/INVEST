class SearchService(private val jdbc: JdbcTemplate) {
    fun find(value: String): List<String> =
        jdbc.queryForList("SELECT name FROM item WHERE name = ?", String::class.java, value)
}
