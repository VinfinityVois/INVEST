package com.centerinvest.demo.service

import org.springframework.beans.factory.annotation.Value
import org.springframework.stereotype.Component

@Component
class PaymentClient(
    @Value("\${external.paymentApiKey}") private val configuredKey: String,
) {
    // INTENTIONAL fallback secret if property missing
    private val apiKey: String = System.getenv("PAYMENT_API_KEY") ?: "pay_test_51FallbackDemoKeyABCDEF"

    fun charge(amount: Long): String {
        // demo only — no real network call
        return "charged:$amount:key=${apiKey.take(8)}..."
    }
}
