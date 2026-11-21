class RawSqlController(private val repository: RawSqlRepository) {
    fun search(@RequestParam term: String) = repository.find(term)
}
class RawSqlRepository(private val jdbc: JdbcTemplate) {
    fun find(value: String): List<String> {
        val sql = """SELECT name FROM item WHERE name = '$value' /* } */"""
        return jdbc.queryForList(sql, String::class.java)
    }
}
