from app.scanners.sast import scan_kotlin_project


def test_detects_five_kotlin_spring_security_cases_without_control_hits(tmp_path):
    root = tmp_path / "project"
    (root / "src/main/kotlin/lab/repairdesk/repair").mkdir(parents=True)
    (root / "src/main/kotlin/lab/repairdesk/integration").mkdir(parents=True)
    (root / "src/main/kotlin/lab/repairdesk/config").mkdir(parents=True)
    (root / "src/main/kotlin/lab/repairdesk/pickup").mkdir(parents=True)

    (root / "src/main/kotlin/lab/repairdesk/repair/RepairLookupController.kt").write_text(
        """package sample
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.jdbc.core.JdbcTemplate
class RepairLookupController(private val jdbc: JdbcTemplate) {
    fun find(@RequestParam frameTag: String): List<String> =
        jdbc.queryForList("SELECT ticket_code FROM repair_ticket WHERE frame_tag = '$frameTag'", String::class.java)
    fun safe(@RequestParam ticketCode: String): List<String> =
        jdbc.queryForList("SELECT ticket_code FROM repair_ticket WHERE ticket_code = ?", String::class.java, ticketCode)
}
""", encoding="utf-8")

    (root / "src/main/kotlin/lab/repairdesk/integration/SupplierHttpsClient.kt").write_text(
        """import javax.net.ssl.HostnameVerifier
class SupplierHttpsClient {
    fun connect() {
        connection.hostnameVerifier = HostnameVerifier { _, _ -> true }
    }
}
""", encoding="utf-8")

    (root / "src/main/kotlin/lab/repairdesk/config/RepairCors.kt").write_text(
        """class RepairCors {
    fun corsConfigurationSource() {
        val customerSummary = CorsConfiguration().apply {
            allowedOriginPatterns = listOf("*")
            allowCredentials = true
            allowedMethods = listOf("GET")
        }
        source.registerCorsConfiguration("/api/customer/summary", customerSummary)
    }
}
""", encoding="utf-8")

    (root / "src/main/kotlin/lab/repairdesk/config/RepairSecurity.kt").write_text(
        """class RepairSecurity {
    fun securityFilterChain() {
        rules.requestMatchers(GET, "/api/catalog/services").permitAll()
        rules.requestMatchers(GET, "/api/pickup/export").permitAll()
    }
}
""", encoding="utf-8")

    (root / "src/main/kotlin/lab/repairdesk/pickup/PickupExportController.kt").write_text(
        """class PickupExportController {
    @GetMapping("/api/pickup/export")
    fun export(): List<Map<String, Any?>> = jdbc.queryForList("SELECT customer_id FROM pickup_slot")
}
""", encoding="utf-8")

    (root / "src/main/kotlin/lab/repairdesk/repair/RepairTicketController.kt").write_text(
        """class RepairTicketController(private val reader: RepairTicketReader) {
    @GetMapping("/tickets/{ticketId}")
    fun getTicket(@PathVariable ticketId: Long): ResponseEntity<RepairTicket> =
        ResponseEntity.ofNullable(reader.read(ticketId))
}
""", encoding="utf-8")

    (root / "src/main/kotlin/lab/repairdesk/repair/RepairTicketReader.kt").write_text(
        """class RepairTicketReader {
    fun read(ticketId: Long): RepairTicket? = jdbc.query(
        "SELECT ticket_code, customer_id, work_note FROM repair_ticket WHERE ticket_id = ?",
        mapper, ticketId,
    ).firstOrNull()
}
""", encoding="utf-8")

    findings = scan_kotlin_project(root)
    rules = {item["rule_id"] for item in findings}
    assert rules == {
        "kotlin.jdbc.sql-injection",
        "kotlin.tls.hostname-verification-disabled",
        "kotlin.spring.credentialed-cors-wildcard",
        "kotlin.spring.public-sensitive-route",
        "kotlin.spring.idor.unscoped-object-read",
    }


def test_safe_kotlin_controls_do_not_trigger(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    (root / "Safe.kt").write_text(
        """class Safe {
    fun query(@RequestParam ticketCode: String) =
        jdbc.queryForList("SELECT ticket_code FROM repair_ticket WHERE ticket_code = ?", String::class.java, ticketCode)
    fun tls() { connection.connect() }
    fun publicCatalog() { rules.requestMatchers(GET, "/api/catalog/services").permitAll() }
}
""", encoding="utf-8")
    assert scan_kotlin_project(root) == []



def test_interprocedural_sql_taint_follows_http_input_into_helper(tmp_path):
    from app.scanners.sast import scan_kotlin_project

    root = tmp_path / "project"
    root.mkdir()
    (root / "RepairController.kt").write_text(
        """class RepairController(private val reader: RepairReader) {
    fun lookup(@RequestParam ticketCode: String) = reader.load(ticketCode)
}
class RepairReader(private val jdbc: JdbcTemplate) {
    fun load(code: String): List<String> {
        val sql = "SELECT ticket_code FROM repair_ticket WHERE ticket_code = '$code'"
        return jdbc.queryForList(sql, String::class.java)
    }
}
""", encoding="utf-8"
    )

    findings = scan_kotlin_project(root)
    assert any(item["rule_id"] == "kotlin.taint.interprocedural-sql-injection" for item in findings)


def test_interprocedural_sql_taint_allows_bound_parameters(tmp_path):
    from app.scanners.sast import scan_kotlin_project

    root = tmp_path / "project"
    root.mkdir()
    (root / "SafeController.kt").write_text(
        """class SafeController(private val reader: SafeReader) {
    fun lookup(@RequestParam ticketCode: String) = reader.load(ticketCode)
}
class SafeReader(private val jdbc: JdbcTemplate) {
    fun load(code: String): List<String> =
        jdbc.queryForList("SELECT ticket_code FROM repair_ticket WHERE ticket_code = ?", String::class.java, code)
}
""", encoding="utf-8"
    )

    findings = scan_kotlin_project(root)
    assert not any(item["rule_id"] == "kotlin.taint.interprocedural-sql-injection" for item in findings)


def test_interprocedural_sql_taint_tracks_request_api_source(tmp_path):
    from app.scanners.sast import scan_kotlin_project

    root = tmp_path / "project"
    root.mkdir()
    (root / "RequestHandler.kt").write_text(
        """class RequestHandler(private val service: SearchService) {
    fun search(request: HttpServletRequest) = service.find(request.getParameter("q"))
}
class SearchService(private val jdbc: JdbcTemplate) {
    fun find(term: String): List<String> =
        jdbc.queryForList("SELECT name FROM item WHERE name LIKE '%" + term + "%'", String::class.java)
}
""", encoding="utf-8"
    )

    findings = scan_kotlin_project(root)
    assert any(item["rule_id"] == "kotlin.taint.interprocedural-sql-injection" for item in findings)
