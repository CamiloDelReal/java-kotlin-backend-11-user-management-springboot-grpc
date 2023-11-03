package org.xapps.services.usermanagementservice.services

import com.fasterxml.jackson.databind.ObjectMapper
import com.nimbusds.jose.jwk.source.ImmutableSecret
import com.nimbusds.jose.jwk.source.JWKSource
import com.nimbusds.jose.proc.SecurityContext
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.security.oauth2.jose.jws.MacAlgorithm
import org.springframework.security.oauth2.jwt.*
import org.springframework.stereotype.Service
import org.xapps.services.proto.users.*
import org.xapps.services.usermanagementservice.entities.Role
import org.xapps.services.usermanagementservice.entities.User
import org.xapps.services.usermanagementservice.entities.UserRole
import org.xapps.services.usermanagementservice.repositories.RoleRepository
import org.xapps.services.usermanagementservice.repositories.UserRepository
import org.xapps.services.usermanagementservice.repositories.UserRoleRepository
import org.xapps.services.usermanagementservice.security.SecurityParams
import org.xapps.services.usermanagementservice.services.exceptions.DuplicityException
import org.xapps.services.usermanagementservice.services.exceptions.InvalidCredentialException
import org.xapps.services.usermanagementservice.services.exceptions.UserNotFoundException
import java.time.Instant


@Service
class UserService @Autowired constructor(
    private val userRepository: UserRepository,
    private val roleRepository: RoleRepository,
    private val userRoleRepository: UserRoleRepository,
    private val authenticationManager: AuthenticationManager,
    private val securityParams: SecurityParams,
    private val objectMapper: ObjectMapper,
    private val passwordEncoder: PasswordEncoder
) {

    fun login(credential: LoginRequest): Authorization {
        authenticationManager.authenticate(
            UsernamePasswordAuthenticationToken(credential.email, credential.password)
        )

        return userRepository.findByEmail(credential.email)?.let { user ->
            val currentTimestamp = Instant.now()
            val expiration = currentTimestamp.plusMillis(securityParams.jwtGeneration.validity)
            println(user)
            val subject = objectMapper.writeValueAsString(user)
            println(subject)
            val secretKeySource: JWKSource<SecurityContext> = ImmutableSecret(securityParams.jwtGeneration.key.toByteArray())
            val header = JwsHeader.with(MacAlgorithm.HS256).build()
            val claimsSet = JwtClaimsSet.builder()
                .subject(subject)
                .issuer(securityParams.jwtGeneration.issuer)
                .audience(listOf(securityParams.jwtGeneration.audience))
                .claim(JwtClaimNames.AUD, securityParams.jwtGeneration.audience)
                .claim("resource_access", mapOf(
                    listOf(securityParams.jwtGeneration.audience) to mapOf(
                        "roles" to user.roles.map { it.value }
                    )
                ))
                .issuedAt(currentTimestamp)
                .expiresAt(expiration)
                .build()
            val parameters = JwtEncoderParameters.from(header, claimsSet)
            val jwtEncoder = NimbusJwtEncoder(secretKeySource)
            val jwt = jwtEncoder.encode(parameters)

            Authorization.newBuilder()
                .setExpiration(expiration.toEpochMilli())
                .setType(securityParams.jwtGeneration.type)
                .setToken(jwt.tokenValue)
                .build()
        } ?: run {
            throw InvalidCredentialException("Bad credentials")
        }
    }

    fun readAllUsers(): List<User> =
        userRepository.findAll().onEach { it.passwordProtected = "" }

    fun readUser(request: UserReadRequest): UserResponse? =
        userRepository.findById(request.id).orElse(null)?.let { user ->
            UserResponse.newBuilder()
                .setId(user.id)
                .setName(user.name)
                .setLastname(user.lastname)
                .setEmail(user.email)
                .addAllRoles(user.roles.map { it.value })
                .build()
        } ?: throw UserNotFoundException("User with id=${request.id} not found")

    fun hasAdminRole(userRequest: UserCreateRequest): Boolean {
        return if (userRequest.rolesList != null && userRequest.rolesList!!.isNotEmpty()) {
            val administratorRole = roleRepository.findByValue(Role.ADMINISTRATOR)
            administratorRole != null && userRequest.rolesList!!.stream()
                .anyMatch { value -> value == administratorRole.value }
        } else {
            false
        }
    }

    fun hasAdminRole(userRequest: UserUpdateRequest): Boolean {
        return if (userRequest.rolesList != null && userRequest.rolesList!!.isNotEmpty()) {
            val administratorRole = roleRepository.findByValue(Role.ADMINISTRATOR)
            administratorRole != null && userRequest.rolesList!!.stream()
                .anyMatch { value -> value == administratorRole.value }
        } else {
            false
        }
    }

    fun hasAdminRole(user: User): Boolean {
        return if (user.roles.isNotEmpty()) {
            val administratorRole = roleRepository.findByValue(Role.ADMINISTRATOR)
            administratorRole != null && user.roles.stream().anyMatch { role -> role.id == administratorRole.id }
        } else {
            false
        }
    }

    fun createUser(request: UserCreateRequest): UserResponse {
        val duplicity = userRepository.findByEmail(request.email)
        return duplicity?.let {
            throw DuplicityException("Email " + request.email + " is not available")
        } ?: run {
            var roles: List<Role>? = null
            if (!request.rolesList.isNullOrEmpty()) {
                roles = roleRepository.findByValues(request.rolesList!!)
            }
            if (roles.isNullOrEmpty()) {
                val guestRole = roleRepository.findByValue(Role.GUEST)
                roles = listOf(guestRole!!)
            }
            val user = User(
                name = request.name,
                lastname = request.lastname,
                email = request.email,
                passwordProtected = passwordEncoder.encode(request.password),
                roles = roles
            )
            userRepository.save(user)
            val userRoles = roles.map {
                UserRole(id = UserRole.UserRoleId(userId = user.id, roleId = it.id))
            }
            userRoleRepository.saveAll(userRoles)

            UserResponse.newBuilder()
                .setId(user.id)
                .setName(user.name)
                .setLastname(user.lastname)
                .setEmail(user.email)
                .addAllRoles(user.roles.map { it.value })
                .build()
        }
    }

    fun updateUser(request: UserUpdateRequest): UserResponse {
        val userContainer = userRepository.findById(request.id)
        return if (userContainer.isPresent) {
            if (request.email != null) {
                val duplicity = userRepository.findByIdNotAndEmail(request.id, request.email!!)
                duplicity?.let {
                    throw DuplicityException("Email=${request.email} is not available")
                }
            }

            val user = userContainer.get()
            request.name?.let { user.name = it }
            request.lastname?.let { user.lastname = it }
            request.email?.let { user.email = it }
            request.password?.let { user.passwordProtected = passwordEncoder.encode(it) }

            if (request.rolesList != null && request.rolesList!!.isNotEmpty()) {
                val roles = roleRepository.findByValues(request.rolesList!!)
                if (roles.isNotEmpty()) {
                    userRoleRepository.deleteRolesByUserId(user.id)
                    userRoleRepository.saveAll(roles.map { role: Role -> UserRole(UserRole.UserRoleId(user.id, role.id)) })
                }
            }
            userRepository.save(user)

            UserResponse.newBuilder()
                .setId(user.id)
                .setName(user.name)
                .setLastname(user.lastname)
                .setEmail(user.email)
                .addAllRoles(user.roles.map { it.value })
                .build()
        } else {
            throw UserNotFoundException("Nonexistent user with id=${request.id}")
        }
    }

    fun delete(request: UserDeleteRequest) {
        val userContainer = userRepository.findById(request.id)
        if (userContainer.isPresent) {
            userRoleRepository.deleteRolesByUserId(userContainer.get().id)
            userRepository.delete(userContainer.get())
        } else {
            throw UserNotFoundException("Nonexistent user with id=${request.id}")
        }
    }

}