package org.xapps.services.usermanagementservice.security

import org.lognet.springboot.grpc.security.GrpcSecurity
import org.lognet.springboot.grpc.security.GrpcSecurityConfigurerAdapter
import org.lognet.springboot.grpc.security.jwt.JwtAuthProviderFactory
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.security.authentication.dao.DaoAuthenticationProvider
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.security.oauth2.jwt.JwtDecoder
import org.springframework.stereotype.Component

@Component
class GrpcSecurityConfigurerAdapterImpl @Autowired constructor(
    private val userDetailsService: UserDetailsService,
    private val passwordEncoder: PasswordEncoder,
    private val jwtDecoder: JwtDecoder
) : GrpcSecurityConfigurerAdapter() {

    override fun configure(builder: GrpcSecurity) {
        builder
            .userDetailsService(userDetailsService)
            .authenticationProvider(
                DaoAuthenticationProvider().apply {
                    setUserDetailsService(userDetailsService)
                    setPasswordEncoder(passwordEncoder)
                }
            )

            .authenticationProvider(JwtAuthProviderFactory.forRoles(jwtDecoder))
            .authorizeRequests().withSecuredAnnotation()
    }

}