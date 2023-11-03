package org.xapps.services.usermanagementservice.controllers.exceptionhandlers

import io.grpc.Status
import org.lognet.springboot.grpc.recovery.GRpcExceptionHandler
import org.lognet.springboot.grpc.recovery.GRpcExceptionScope
import org.lognet.springboot.grpc.recovery.GRpcServiceAdvice
import org.springframework.security.access.AccessDeniedException
import org.springframework.security.core.AuthenticationException
import org.xapps.services.usermanagementservice.services.exceptions.*


@GRpcServiceAdvice
class GlobalExceptionHandler {

    @GRpcExceptionHandler
    fun handle(ex: Exception, scope: GRpcExceptionScope?): Status {
        return when(ex) {
            is DuplicityException -> Status.ALREADY_EXISTS.withDescription(ex.message)
            is ForbiddenException -> Status.PERMISSION_DENIED.withDescription(ex.message)
            is InvalidCredentialException -> Status.UNAUTHENTICATED.withDescription(ex.message)
            is RoleNotFoundException -> Status.NOT_FOUND.withDescription(ex.message)
            is UsernameNotFoundException -> Status.NOT_FOUND.withDescription(ex.message)
            is UserNotFoundException -> Status.NOT_FOUND.withDescription(ex.message)
            is AuthenticationException -> Status.UNAUTHENTICATED.withDescription(ex.message)
            is AccessDeniedException -> Status.PERMISSION_DENIED.withDescription(ex.message)
            else -> Status.INTERNAL.withDescription(ex.message)
        }
    }

}