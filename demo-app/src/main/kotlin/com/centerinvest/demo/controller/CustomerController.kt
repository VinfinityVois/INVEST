package com.centerinvest.demo.controller

import com.centerinvest.demo.service.CustomerService
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PathVariable
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.RestController

@RestController
@RequestMapping("/api")
class CustomerController(
    private val jdbcTemplate: JdbcTemplate,
    private val customerService: CustomerService,
) {

    // INTENTIONAL SQL injection via string concatenation (SAST)
    @GetMapping("/customers/search")
    fun search(@RequestParam name: String): List<Map<String, Any>> {
        val sql = "SELECT * FROM customers WHERE name = '" + name + "'"
        return jdbcTemplate.queryForList(sql)
    }

    // INTENTIONAL: public sensitive export (paired with permitAll in SecurityConfig)
    @GetMapping("/export/customers")
    fun exportAll(): List<Map<String, Any>> {
        return jdbcTemplate.queryForList("SELECT id, email, phone, passport_hash FROM customers")
    }

    // INTENTIONAL IDOR-style read without ownership check
    @GetMapping("/account/{accountId}")
    fun getAccount(@PathVariable accountId: String): Map<String, Any>? {
        return customerService.read(accountId)
    }
}
