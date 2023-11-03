package org.xapps.services.usermanagementservice.controllers

import com.google.protobuf.Empty
import io.grpc.stub.StreamObserver
import org.lognet.springboot.grpc.GRpcService
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.security.access.prepost.PreAuthorize
import org.springframework.security.core.context.SecurityContextHolder
import org.xapps.services.proto.users.*
import org.xapps.services.usermanagementservice.entities.Role
import org.xapps.services.usermanagementservice.security.JwtDecoderImpl
import org.xapps.services.usermanagementservice.services.UserService
import org.xapps.services.usermanagementservice.services.exceptions.ForbiddenException


@GRpcService
class UserController @Autowired constructor(
    private val userService: UserService,
    private val jwtDecoder: JwtDecoderImpl
) : UsersGrpc.UsersImplBase() {

    override fun login(request: LoginRequest, responseObserver: StreamObserver<Authorization>) {
        val authentication = userService.login(request)
        responseObserver.onNext(authentication)
        responseObserver.onCompleted()
    }

    @PreAuthorize("isAuthenticated() and hasRole('${Role.ADMINISTRATOR}')")
    override fun readUsers(request: Empty?, responseObserver: StreamObserver<UserResponse>?) {
    }

    @PreAuthorize("isAuthenticated() and hasAuthority('${Role.ADMINISTRATOR}') or isAuthenticated() and principal.id == #request.id")
    override fun readUser(request: UserReadRequest, responseObserver: StreamObserver<UserResponse>) {
        val userResponse = userService.readUser(request)
        println(userResponse)
        responseObserver.onNext(userResponse)
        responseObserver.onCompleted()
    }

    override fun createUser(request: UserCreateRequest, responseObserver: StreamObserver<UserResponse>) {
        val userAuthenticated = jwtDecoder.extractUser(SecurityContextHolder.getContext().authentication?.principal)
        val requestingUpdateToAdmin = userService.hasAdminRole(request)
        if (!requestingUpdateToAdmin || userAuthenticated != null && userService.hasAdminRole(userAuthenticated)) {
            val userResponse = userService.createUser(request)
            responseObserver.onNext(userResponse)
            responseObserver.onCompleted()
        } else {
            throw ForbiddenException("Authenticated user does not have permission for the requested operation")
        }
    }

    @PreAuthorize("isAuthenticated()")
    override fun updateUser(request: UserUpdateRequest, responseObserver: StreamObserver<UserResponse>) {
        val requestingUpdateToAdmin = userService.hasAdminRole(request)
        val userAuthenticated = jwtDecoder.extractUser(SecurityContextHolder.getContext().authentication?.principal)!!
        if (userService.hasAdminRole(userAuthenticated) || (!requestingUpdateToAdmin && userAuthenticated.id == request.id)) {
            val userResponse = userService.updateUser(request)
            responseObserver.onNext(userResponse)
            responseObserver.onCompleted()
        } else {
            throw ForbiddenException("Authenticated user does not have permission for the requested operation")
        }
    }

    @PreAuthorize("isAuthenticated()")
    override fun deleteUser(request: UserDeleteRequest, responseObserver: StreamObserver<Empty>) {
        val userAuthenticated = jwtDecoder.extractUser(SecurityContextHolder.getContext().authentication?.principal)!!
        if (userService.hasAdminRole(userAuthenticated) || userAuthenticated.id == request.id) {
            userService.delete(request)
            responseObserver.onNext(Empty.getDefaultInstance())
            responseObserver.onCompleted()
        } else {
            throw ForbiddenException("Authenticated user does not have permission for the requested operation")
        }
    }

}