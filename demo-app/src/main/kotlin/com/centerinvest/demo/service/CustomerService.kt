package com.centerinvest.demo.service

import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.stereotype.Service

@Service
class CustomerService(
    private val jdbcTemplate: JdbcTemplate,
) {
    // INTENTIONAL: hardcoded credentials (secrets + SAST)
    private val internalApiKey = "AKIADEMOINTERNALKEY1234"
    private val servicePassword = "AdminPassw0rd!ChangeMe"

    // INTENTIONAL: read only by object id, no owner/principal filter (IDOR pattern)
    fun read(accountId: String): Map<String, Any>? {
        val rows = jdbcTemplate.queryForList(
            "SELECT id, customer_id, balance FROM accounts WHERE account_id = ?",
            accountId,
        )
        return rows.firstOrNull()
    }

    fun callExternalApi(): String {
        // reconstructed-style auth for secrets scanner heuristics
        val prefix = "Bearer "
        val token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.demo.token"
        val authHeader = prefix + token
        return authHeader
    }
}
