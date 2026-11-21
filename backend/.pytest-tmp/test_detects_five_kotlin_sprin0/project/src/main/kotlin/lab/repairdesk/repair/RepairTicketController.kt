class RepairTicketController(private val reader: RepairTicketReader) {
    @GetMapping("/tickets/{ticketId}")
    fun getTicket(@PathVariable ticketId: Long): ResponseEntity<RepairTicket> =
        ResponseEntity.ofNullable(reader.read(ticketId))
}
