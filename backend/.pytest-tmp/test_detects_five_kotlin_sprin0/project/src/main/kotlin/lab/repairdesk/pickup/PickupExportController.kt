class PickupExportController {
    @GetMapping("/api/pickup/export")
    fun export(): List<Map<String, Any?>> = jdbc.queryForList("SELECT customer_id FROM pickup_slot")
}
