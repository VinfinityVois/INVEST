class LookupController {
    fun find(@RequestParam frameTag: String): List<String> =
        jdbc.queryForList("SELECT code FROM repair_ticket WHERE frame_tag = '$frameTag'", String::class.java)
}
