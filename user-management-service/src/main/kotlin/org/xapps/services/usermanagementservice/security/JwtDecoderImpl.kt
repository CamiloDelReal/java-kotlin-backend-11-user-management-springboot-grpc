package org.xapps.services.usermanagementservice.security

import com.fasterxml.jackson.databind.ObjectMapper
import com.nimbusds.jose.jwk.source.ImmutableSecret
import com.nimbusds.jose.proc.SecurityContext
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.security.oauth2.jwt.Jwt
import org.springframework.security.oauth2.jwt.JwtDecoder
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder
import org.springframework.stereotype.Component
import org.xapps.services.usermanagementservice.entities.User
import org.xapps.services.usermanagementservice.services.exceptions.InvalidCredentialException

@Component
class JwtDecoderImpl @Autowired constructor(
    private val securityParams: SecurityParams,
    private val objectMapper: ObjectMapper
): JwtDecoder {

    private val secretKey = ImmutableSecret<SecurityContext>(securityParams.jwtGeneration.key.toByteArray()).secretKey
    private val jwtDecoder = NimbusJwtDecoder.withSecretKey(secretKey).build()

    override fun decode(token: String?): Jwt {
        return try {
            jwtDecoder.decode(token)
        } catch (ex: Exception) {
            throw InvalidCredentialException("Invalid token")
        }
    }

    fun extractUser(token: String?): User? {
        return token?.let {
            try {
                val claims = jwtDecoder.decode(token)
                val subject = claims.subject
                objectMapper.readValue(subject, User::class.java)
            } catch (ex: Exception) {
                ex.printStackTrace()
                throw InvalidCredentialException("Invalid token")
            }
        }
    }

    fun extractUser(jwt: Jwt?): User? {
        return jwt?.let {
            try {
                objectMapper.readValue(jwt.subject, User::class.java)
            } catch (ex: Exception) {
                ex.printStackTrace()
                throw InvalidCredentialException("Invalid token")
            }
        }
    }

    fun extractUser(auth: Any?): User? {
        return when(auth) {
            is String -> extractUser(auth)
            is Jwt -> extractUser(auth)
            else -> throw Exception("Invalid Jwt claim type")
        }
    }
}