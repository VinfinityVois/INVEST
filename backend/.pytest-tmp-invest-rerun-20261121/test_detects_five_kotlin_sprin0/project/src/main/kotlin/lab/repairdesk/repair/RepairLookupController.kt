package sample
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.jdbc.core.JdbcTemplate
class RepairLookupController(private val jdbc: JdbcTemplate) {
    fun find(@RequestParam frameTag: String): List<String> =
        jdbc.queryForList("SELECT ticket_code FROM repair_ticket WHERE frame_tag = '$frameTag'", String::class.java)
    fun safe(@RequestParam ticketCode: String): List<String> =
        jdbc.queryForList("SELECT ticket_code FROM repair_ticket WHERE ticket_code = ?", String::class.java, ticketCode)
}
