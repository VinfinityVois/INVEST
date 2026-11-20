package com.centerinvest.demo.config

import okhttp3.OkHttpClient
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import javax.net.ssl.HostnameVerifier

@Configuration
class HttpClientConfig {

    @Bean
    fun unsafeHttpClient(): OkHttpClient {
        // INTENTIONAL: hostname verification disabled (SAST)
        val hostnameVerifier = HostnameVerifier { _, _ -> true }
        return OkHttpClient.Builder()
            .hostnameVerifier(hostnameVerifier)
            .build()
    }
}
