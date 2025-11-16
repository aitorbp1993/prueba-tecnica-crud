package com.aitorbartolome.prueba_tecnica_crud.security;

import com.aitorbartolome.prueba_tecnica_crud.security.constants.JwtConstants;
import com.aitorbartolome.prueba_tecnica_crud.exception.JwtException;
import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.util.*;
import java.util.function.Function;

/**
 * The type Jwt provider.
 */
@Slf4j
@Service
public class JwtProvider {

    @Value("${jwt.secret}")
    private String jwtSecret;

    @Value("${jwt.expiration}")
    private long jwtExpiration;

    @Value("${jwt.refresh-expiration:604800000}")
    private long refreshExpiration;

    /**
     * Generate access token string.
     *
     * @param username the username
     * @param userId   the user id
     * @param email    the email
     * @param roles    the roles
     * @return the string
     */
    public String generateAccessToken(String username, UUID userId, String email, List<String> roles) {
        Map<String, Object> claims = new HashMap<>();
        claims.put(JwtConstants.CLAIM_ROLES, roles);
        claims.put(JwtConstants.CLAIM_USER_ID, userId.toString());
        claims.put(JwtConstants.CLAIM_EMAIL, email);
        claims.put(JwtConstants.CLAIM_TOKEN_TYPE, JwtConstants.TOKEN_TYPE_ACCESS);

        return generateToken(claims, username, jwtExpiration);
    }

    /**
     * Generate refresh token string.
     *
     * @param username the username
     * @param userId   the user id
     * @return the string
     */
    public String generateRefreshToken(String username, UUID userId) {
        Map<String, Object> claims = new HashMap<>();
        claims.put(JwtConstants.CLAIM_USER_ID, userId.toString());
        claims.put(JwtConstants.CLAIM_TOKEN_TYPE, JwtConstants.TOKEN_TYPE_REFRESH);

        return generateToken(claims, username, refreshExpiration);
    }

    private String generateToken(Map<String, Object> claims, String username, long expiration) {
        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + expiration);

        String token = Jwts.builder()
                .claims(claims)
                .subject(username)
                .issuedAt(now)
                .expiration(expiryDate)
                .signWith(getSigningKey())
                .compact();

        log.debug("Token generado para usuario: {}", username);
        return token;
    }

    /**
     * Extract username string.
     *
     * @param token the token
     * @return the string
     */
    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    /**
     * Extract user id uuid.
     *
     * @param token the token
     * @return the uuid
     */
    public UUID extractUserId(String token) {
        String userId = extractClaim(token, claims -> (String) claims.get(JwtConstants.CLAIM_USER_ID));
        try {
            return UUID.fromString(userId);
        } catch (IllegalArgumentException e) {
            log.warn("UUID inválido en token: {}", userId);
            throw new JwtException("UUID inválido en token", "INVALID_USER_ID", e);
        }
    }

    /**
     * Extrae los roles del token
     *
     * @param token the token
     * @return the list
     */
    @SuppressWarnings("unchecked")
    public List<String> extractRoles(String token) {
        List<String> roles = extractClaim(token, claims -> (List<String>) claims.get(JwtConstants.CLAIM_ROLES));
        return roles != null ? roles : new ArrayList<>();
    }

    /**
     * Valida si el token es válido para un username específico
     *
     * @param token    the token
     * @param username the username
     * @return the boolean
     */
    public boolean isTokenValid(String token, String username) {
        try {
            final String usernameFromToken = extractUsername(token);
            final String tokenType = extractClaim(token, claims -> (String) claims.get(JwtConstants.CLAIM_TOKEN_TYPE));

            return usernameFromToken.equals(username)
                    && !isTokenExpired(token)
                    && JwtConstants.TOKEN_TYPE_ACCESS.equals(tokenType);
        } catch (Exception e) {
            log.warn("Token inválido para usuario: {}", username);
            return false;
        }
    }

    /**
     * Valida si el refresh token es válido
     *
     * @param token    the token
     * @param username the username
     * @return the boolean
     */
    public boolean isRefreshTokenValid(String token, String username) {
        try {
            final String usernameFromToken = extractUsername(token);
            final String tokenType = extractClaim(token, claims -> (String) claims.get(JwtConstants.CLAIM_TOKEN_TYPE));

            return usernameFromToken.equals(username)
                    && !isTokenExpired(token)
                    && JwtConstants.TOKEN_TYPE_REFRESH.equals(tokenType);
        } catch (Exception e) {
            log.warn("Refresh token inválido para usuario: {}", username);
            return false;
        }
    }

    /**
     * Valida la estructura y firma del token
     *
     * @param token the token
     */
    public void validateTokenStructure(String token) {
        try {
            Jwts.parser()
                    .verifyWith(getSigningKey())
                    .build()
                    .parseSignedClaims(token);
        } catch (ExpiredJwtException e) {
            log.warn("Token expirado");
            throw new JwtException(JwtConstants.ERROR_TOKEN_EXPIRED, "EXPIRED_TOKEN");
        } catch (UnsupportedJwtException e) {
            log.warn("Token JWT no soportado");
            throw new JwtException(JwtConstants.ERROR_TOKEN_UNSIGNED, "UNSUPPORTED_TOKEN");
        } catch (MalformedJwtException e) {
            log.warn("Token JWT malformado");
            throw new JwtException(JwtConstants.ERROR_TOKEN_INVALID, "MALFORMED_TOKEN");
        } catch (SignatureException e) {
            log.warn("Firma JWT inválida");
            throw new JwtException(JwtConstants.ERROR_TOKEN_INVALID, "INVALID_SIGNATURE");
        } catch (IllegalArgumentException e) {
            log.warn("Claims vacíos en JWT");
            throw new JwtException(JwtConstants.ERROR_TOKEN_CLAIMS_EMPTY, "EMPTY_CLAIMS");
        } catch (JwtException e) {
            throw e;
        } catch (Exception e) {
            log.error("Error inesperado validando token", e);
            throw new JwtException(JwtConstants.ERROR_TOKEN_INVALID, "UNKNOWN_ERROR");
        }
    }

    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    private Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    private <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    private Claims extractAllClaims(String token) {
        return Jwts.parser()
                .verifyWith(getSigningKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    private SecretKey getSigningKey() {
        byte[] keyBytes = Decoders.BASE64.decode(jwtSecret);
        return Keys.hmacShaKeyFor(keyBytes);
    }
}
