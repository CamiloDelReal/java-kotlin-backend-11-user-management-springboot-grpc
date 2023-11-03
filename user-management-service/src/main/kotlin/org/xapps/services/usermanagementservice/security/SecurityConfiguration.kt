package org.xapps.services.usermanagementservice.security

import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.authentication.ProviderManager
import org.springframework.security.authentication.dao.DaoAuthenticationProvider
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder
import org.springframework.security.crypto.password.PasswordEncoder


@Configuration
@EnableMethodSecurity(prePostEnabled = true)
class SecurityConfiguration {

    @Bean
    fun providePasswordEncoder(): PasswordEncoder = BCryptPasswordEncoder()

    @Bean
    fun authenticationManager(userDetailsService: UserDetailsService): AuthenticationManager =
        ProviderManager(listOf(DaoAuthenticationProvider().apply {
            setUserDetailsService(userDetailsService)
            setPasswordEncoder(providePasswordEncoder())
        }))

}