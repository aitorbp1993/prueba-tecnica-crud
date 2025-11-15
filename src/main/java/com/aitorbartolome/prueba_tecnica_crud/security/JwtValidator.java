package com.aitorbartolome.prueba_tecnica_crud.security;

import com.aitorbartolome.prueba_tecnica_crud.security.constants.JwtConstants;
import io.jsonwebtoken.JwtException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

@Slf4j
@Component
public class JwtValidator {

    public String extractBearerToken(String authHeader) {
        if (authHeader == null || authHeader.isEmpty()) {
            log.debug("Header de autorización vacío");
            return null;
        }

        if (!authHeader.startsWith(JwtConstants.BEARER_PREFIX)) {
            log.warn("Header no contiene el prefijo Bearer");
            throw new JwtException(JwtConstants.ERROR_TOKEN_NOT_BEARER);
        }

        return authHeader.substring(JwtConstants.BEARER_PREFIX_LENGTH);
    }

    public void validateTokenHasRoles(String token, JwtProvider jwtProvider) {
        var roles = jwtProvider.extractRoles(token);
        if (roles.isEmpty()) {
            log.warn("Token sin roles asignados");
            throw new JwtException("Token sin roles");
        }
    }
}
