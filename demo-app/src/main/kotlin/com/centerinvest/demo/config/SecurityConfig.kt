package com.centerinvest.demo.config

import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.web.SecurityFilterChain
import org.springframework.web.cors.CorsConfiguration
import org.springframework.web.cors.UrlBasedCorsConfigurationSource
import org.springframework.web.filter.CorsFilter

@Configuration
@EnableWebSecurity
class SecurityConfig {

    @Bean
    fun filterChain(http: HttpSecurity): SecurityFilterChain {
        http
            .csrf { it.disable() }
            .authorizeHttpRequests { auth ->
                auth
                    // INTENTIONAL: sensitive routes left public for SAST demo
                    .requestMatchers("/api/export/customers").permitAll()
                    .requestMatchers("/api/admin/**").permitAll()
                    .requestMatchers("/api/account/**").permitAll()
                    .anyRequest().authenticated()
            }
        return http.build()
    }

    @Bean
    fun corsFilter(): CorsFilter {
        val source = UrlBasedCorsConfigurationSource()
        val config = CorsConfiguration()
        // INTENTIONAL: wildcard origin + credentials
        config.allowedOriginPatterns = listOf("*")
        config.allowCredentials = true
        config.addAllowedHeader("*")
        config.addAllowedMethod("*")
        source.registerCorsConfiguration("/api/customer/**", config)
        source.registerCorsConfiguration("/api/account/**", config)
        return CorsFilter(source)
    }
}
