class RepairTicketReader {
    fun read(ticketId: Long): RepairTicket? = jdbc.query(
        "SELECT ticket_code, customer_id, work_note FROM repair_ticket WHERE ticket_id = ?",
        mapper, ticketId,
    ).firstOrNull()
}
