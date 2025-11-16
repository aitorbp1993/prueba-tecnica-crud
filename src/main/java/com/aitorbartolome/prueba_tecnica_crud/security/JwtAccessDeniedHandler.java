package com.aitorbartolome.prueba_tecnica_crud.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.aitorbartolome.prueba_tecnica_crud.exception.ErrorCode;
import com.aitorbartolome.prueba_tecnica_crud.exception.ErrorResponse;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.time.Instant;

/**
 * The type Jwt access denied handler.
 */
@Slf4j
@Component
public class JwtAccessDeniedHandler implements AccessDeniedHandler {

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Override
    public void handle(
            HttpServletRequest request,
            HttpServletResponse response,
            AccessDeniedException accessDeniedException) throws IOException, ServletException {

        log.warn("Access denied for request to {}: {}", request.getRequestURI(), accessDeniedException.getMessage());

        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setStatus(HttpServletResponse.SC_FORBIDDEN);

        ErrorResponse errorResponse = ErrorResponse.builder()
                .timestamp(Instant.now().toString())
                .status(HttpServletResponse.SC_FORBIDDEN)
                .error("FORBIDDEN")
                .message("Access denied. You do not have permission to access this resource.")
                .path(request.getRequestURI())
                .code(ErrorCode.AUTHZ_001.getCode())
                .details("Ensure your JWT token is valid and has not expired")
                .build();

        response.getWriter().write(objectMapper.writeValueAsString(errorResponse));
        response.getWriter().flush();
    }
}
