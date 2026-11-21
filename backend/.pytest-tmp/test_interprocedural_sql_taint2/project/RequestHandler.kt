class RequestHandler(private val service: SearchService) {
    fun search(request: HttpServletRequest) = service.find(request.getParameter("q"))
}
class SearchService(private val jdbc: JdbcTemplate) {
    fun find(term: String): List<String> =
        jdbc.queryForList("SELECT name FROM item WHERE name LIKE '%" + term + "%'", String::class.java)
}
