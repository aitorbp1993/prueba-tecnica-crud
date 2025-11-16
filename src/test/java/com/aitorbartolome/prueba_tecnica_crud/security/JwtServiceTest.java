package com.aitorbartolome.prueba_tecnica_crud.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SignatureException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Date;

import static org.junit.jupiter.api.Assertions.*;

@ExtendWith(MockitoExtension.class)
@DisplayName("JwtService Tests")
class JwtServiceTest {

    private JwtService jwtService;

    private static final String TEST_SECRET = generateBase64Secret();
    private static final long JWT_EXPIRATION = 3600000; // 1 hour in milliseconds
    private static final String TEST_USERNAME = "testuser";

    @BeforeEach
    void setUp() {
        jwtService = new JwtService();
        ReflectionTestUtils.setField(jwtService, "jwtSecret", TEST_SECRET);
        ReflectionTestUtils.setField(jwtService, "jwtExpiration", JWT_EXPIRATION);
    }

    /**
     * Generate a valid Base64 encoded secret key for HMAC-SHA algorithms
     */
    private static String generateBase64Secret() {
        String secret = "MyVerySecureSecretKeyForJWTTokenGenerationAndValidation12345";
        return Base64.getEncoder().encodeToString(secret.getBytes(StandardCharsets.UTF_8));
    }

    @Nested
    @DisplayName("Token Generation Tests")
    class TokenGenerationTests {

        @Test
        @DisplayName("Should successfully generate a valid JWT token")
        void shouldGenerateValidJwtToken() {
            // Act
            String token = jwtService.generateToken(TEST_USERNAME);

            // Assert
            assertNotNull(token);
            assertFalse(token.isEmpty());
            assertTrue(token.split("\\.").length == 3); // JWT has 3 parts: header.payload.signature
        }

        @Test
        @DisplayName("Should generate token with correct username in subject")
        void shouldGenerateTokenWithCorrectUsername() {
            // Act
            String token = jwtService.generateToken(TEST_USERNAME);
            String extractedUsername = jwtService.extractUsername(token);

            // Assert
            assertEquals(TEST_USERNAME, extractedUsername);
        }

        @Test
        @DisplayName("Should generate token with expiration date")
        void shouldGenerateTokenWithExpirationDate() {
            // Arrange
            Date beforeGeneration = new Date();

            // Act
            String token = jwtService.generateToken(TEST_USERNAME);

            // Assert
            Claims claims = Jwts.parser()
                    .verifyWith(getSigningKey())
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();

            assertNotNull(claims.getExpiration());
            assertTrue(claims.getExpiration().after(beforeGeneration));
        }

        @Test
        @DisplayName("Should generate token with issued at date")
        void shouldGenerateTokenWithIssuedAtDate() {
            // Arrange
            long beforeGeneration = System.currentTimeMillis();

            // Act
            String token = jwtService.generateToken(TEST_USERNAME);

            // Assert
            Claims claims = Jwts.parser()
                    .verifyWith(getSigningKey())
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();

            assertNotNull(claims.getIssuedAt());
            assertTrue(claims.getIssuedAt().getTime() <= System.currentTimeMillis());
        }

        @Test
        @DisplayName("Should generate different tokens for different usernames")
        void shouldGenerateDifferentTokensForDifferentUsernames() {
            // Act
            String token1 = jwtService.generateToken("user1");
            String token2 = jwtService.generateToken("user2");

            // Assert
            assertNotEquals(token1, token2);
            assertEquals("user1", jwtService.extractUsername(token1));
            assertEquals("user2", jwtService.extractUsername(token2));
        }

        @Test
        @DisplayName("Should generate token with correct expiration time")
        void shouldGenerateTokenWithCorrectExpirationTime() {
            // Arrange
            long beforeGeneration = System.currentTimeMillis();

            // Act
            String token = jwtService.generateToken(TEST_USERNAME);

            // Assert
            Claims claims = Jwts.parser()
                    .verifyWith(getSigningKey())
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();

            long expectedExpiration = beforeGeneration + JWT_EXPIRATION;
            long actualExpiration = claims.getExpiration().getTime();

            // Allow 1 second tolerance
            assertTrue(Math.abs(expectedExpiration - actualExpiration) < 1000);
        }
    }

    @Nested
    @DisplayName("Extract Username Tests")
    class ExtractUsernameTests {

        @Test
        @DisplayName("Should successfully extract username from valid token")
        void shouldExtractUsernameFromValidToken() {
            // Arrange
            String token = jwtService.generateToken(TEST_USERNAME);

            // Act
            String extractedUsername = jwtService.extractUsername(token);

            // Assert
            assertEquals(TEST_USERNAME, extractedUsername);
        }

        @Test
        @DisplayName("Should extract different usernames from different tokens")
        void shouldExtractDifferentUsernamesFromDifferentTokens() {
            // Arrange
            String token1 = jwtService.generateToken("alice");
            String token2 = jwtService.generateToken("bob");

            // Act
            String username1 = jwtService.extractUsername(token1);
            String username2 = jwtService.extractUsername(token2);

            // Assert
            assertEquals("alice", username1);
            assertEquals("bob", username2);
        }

        @Test
        @DisplayName("Should throw exception when extracting username from malformed token")
        void shouldThrowExceptionWhenExtractingUsernameFromMalformedToken() {
            // Arrange
            String malformedToken = "invalid.token.here";

            // Act & Assert
            assertThrows(MalformedJwtException.class, () -> {
                jwtService.extractUsername(malformedToken);
            });
        }

        @Test
        @DisplayName("Should throw exception when extracting username from token with invalid signature")
        void shouldThrowExceptionWhenExtractingUsernameFromTokenWithInvalidSignature() {
            // Arrange
            String token = jwtService.generateToken(TEST_USERNAME);
            String tamperedToken = token.substring(0, token.length() - 5) + "XXXXX";

            // Act & Assert
            assertThrows(SignatureException.class, () -> {
                jwtService.extractUsername(tamperedToken);
            });
        }

        @Test
        @DisplayName("Should extract username from expired token")
        void shouldExtractUsernameFromExpiredToken() {
            // Arrange
            String expiredToken = generateExpiredToken(TEST_USERNAME);

            // Act & Assert
            assertThrows(ExpiredJwtException.class, () -> {
                jwtService.extractUsername(expiredToken);
            });
        }
    }

    @Nested
    @DisplayName("Token Validation Tests")
    class TokenValidationTests {

        @Test
        @DisplayName("Should validate token successfully with correct username")
        void shouldValidateTokenSuccessfullyWithCorrectUsername() {
            // Arrange
            String token = jwtService.generateToken(TEST_USERNAME);

            // Act
            boolean isValid = jwtService.isTokenValid(token, TEST_USERNAME);

            // Assert
            assertTrue(isValid);
        }

        @Test
        @DisplayName("Should invalidate token with incorrect username")
        void shouldInvalidateTokenWithIncorrectUsername() {
            // Arrange
            String token = jwtService.generateToken(TEST_USERNAME);

            // Act
            boolean isValid = jwtService.isTokenValid(token, "wronguser");

            // Assert
            assertFalse(isValid);
        }

        @Test
        @DisplayName("Should invalidate expired token")
        void shouldInvalidateExpiredToken() {
            // Arrange
            String expiredToken = generateExpiredToken(TEST_USERNAME);

            // Act & Assert
            assertThrows(ExpiredJwtException.class, () -> {
                jwtService.isTokenValid(expiredToken, TEST_USERNAME);
            });
        }

        @Test
        @DisplayName("Should validate multiple tokens independently")
        void shouldValidateMultipleTokensIndependently() {
            // Arrange
            String token1 = jwtService.generateToken("user1");
            String token2 = jwtService.generateToken("user2");

            // Act
            boolean isValid1 = jwtService.isTokenValid(token1, "user1");
            boolean isValid2 = jwtService.isTokenValid(token2, "user2");
            boolean isInvalid1 = jwtService.isTokenValid(token1, "user2");
            boolean isInvalid2 = jwtService.isTokenValid(token2, "user1");

            // Assert
            assertTrue(isValid1);
            assertTrue(isValid2);
            assertFalse(isInvalid1);
            assertFalse(isInvalid2);
        }

        @Test
        @DisplayName("Should throw exception when validating malformed token")
        void shouldThrowExceptionWhenValidatingMalformedToken() {
            // Arrange
            String malformedToken = "not.a.valid.token";

            // Act & Assert
            assertThrows(MalformedJwtException.class, () -> {
                jwtService.isTokenValid(malformedToken, TEST_USERNAME);
            });
        }

        @Test
        @DisplayName("Should throw exception when validating token with invalid signature")
        void shouldThrowExceptionWhenValidatingTokenWithInvalidSignature() {
            // Arrange
            String token = jwtService.generateToken(TEST_USERNAME);
            String tamperedToken = token.substring(0, token.length() - 10) + "XXXXXXXXXX";

            // Act & Assert
            assertThrows(SignatureException.class, () -> {
                jwtService.isTokenValid(tamperedToken, TEST_USERNAME);
            });
        }
    }

    @Nested
    @DisplayName("Token Expiration Tests")
    class TokenExpirationTests {

        @Test
        @DisplayName("Should create non-expired token")
        void shouldCreateNonExpiredToken() {
            // Arrange
            String token = jwtService.generateToken(TEST_USERNAME);

            // Act
            boolean isValid = jwtService.isTokenValid(token, TEST_USERNAME);

            // Assert
            assertTrue(isValid);
        }

        @Test
        @DisplayName("Should detect expired token")
        void shouldDetectExpiredToken() {
            // Arrange
            String expiredToken = generateExpiredToken(TEST_USERNAME);

            // Act & Assert
            assertThrows(ExpiredJwtException.class, () -> {
                jwtService.isTokenValid(expiredToken, TEST_USERNAME);
            });
        }

        @Test
        @DisplayName("Should create token that expires in the future")
        void shouldCreateTokenThatExpiresInTheFuture() {
            // Arrange
            String token = jwtService.generateToken(TEST_USERNAME);

            // Act
            Claims claims = Jwts.parser()
                    .verifyWith(getSigningKey())
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();

            // Assert
            assertTrue(claims.getExpiration().after(new Date()));
        }
    }

    @Nested
    @DisplayName("Edge Cases and Integration Tests")
    class EdgeCasesTests {

        @Test
        @DisplayName("Should handle username with special characters")
        void shouldHandleUsernameWithSpecialCharacters() {
            // Arrange
            String specialUsername = "user@example.com";

            // Act
            String token = jwtService.generateToken(specialUsername);
            String extractedUsername = jwtService.extractUsername(token);
            boolean isValid = jwtService.isTokenValid(token, specialUsername);

            // Assert
            assertEquals(specialUsername, extractedUsername);
            assertTrue(isValid);
        }

        @Test
        @DisplayName("Should handle username with spaces")
        void shouldHandleUsernameWithSpaces() {
            // Arrange
            String usernameWithSpaces = "user name";

            // Act
            String token = jwtService.generateToken(usernameWithSpaces);
            String extractedUsername = jwtService.extractUsername(token);
            boolean isValid = jwtService.isTokenValid(token, usernameWithSpaces);

            // Assert
            assertEquals(usernameWithSpaces, extractedUsername);
            assertTrue(isValid);
        }

        @Test
        @DisplayName("Should handle long username")
        void shouldHandleLongUsername() {
            // Arrange
            String longUsername = "a".repeat(500);

            // Act
            String token = jwtService.generateToken(longUsername);
            String extractedUsername = jwtService.extractUsername(token);
            boolean isValid = jwtService.isTokenValid(token, longUsername);

            // Assert
            assertEquals(longUsername, extractedUsername);
            assertTrue(isValid);
        }

        @Test
        @DisplayName("Should handle username case sensitivity")
        void shouldHandleUsernameCaseSensitivity() {
            // Arrange
            String token = jwtService.generateToken("TestUser");

            // Act
            boolean isValidWithCorrectCase = jwtService.isTokenValid(token, "TestUser");
            boolean isValidWithLowerCase = jwtService.isTokenValid(token, "testuser");

            // Assert
            assertTrue(isValidWithCorrectCase);
            assertFalse(isValidWithLowerCase);
        }

        @Test
        @DisplayName("Should verify token structure has three parts")
        void shouldVerifyTokenStructureHasThreeParts() {
            // Act
            String token = jwtService.generateToken(TEST_USERNAME);
            String[] parts = token.split("\\.");

            // Assert
            assertEquals(3, parts.length);
            assertFalse(parts[0].isEmpty()); // Header
            assertFalse(parts[1].isEmpty()); // Payload
            assertFalse(parts[2].isEmpty()); // Signature
        }

        @Test
        @DisplayName("Should throw exception for null token")
        void shouldThrowExceptionForNullToken() {
            // Act & Assert
            assertThrows(Exception.class, () -> {
                jwtService.extractUsername(null);
            });
        }

        @Test
        @DisplayName("Should throw exception for empty token")
        void shouldThrowExceptionForEmptyToken() {
            // Act & Assert
            assertThrows(Exception.class, () -> {
                jwtService.extractUsername("");
            });
        }

        @Test
        @DisplayName("Should verify issued at is before expiration")
        void shouldVerifyIssuedAtIsBeforeExpiration() {
            // Act
            String token = jwtService.generateToken(TEST_USERNAME);

            Claims claims = Jwts.parser()
                    .verifyWith(getSigningKey())
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();

            // Assert
            assertTrue(claims.getIssuedAt().before(claims.getExpiration()));
        }

        @Test
        @DisplayName("Should verify expiration is exactly JWT_EXPIRATION after issued at")
        void shouldVerifyExpirationIsExactlyJwtExpirationAfterIssuedAt() {
            // Act
            String token = jwtService.generateToken(TEST_USERNAME);

            Claims claims = Jwts.parser()
                    .verifyWith(getSigningKey())
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();

            long issuedAt = claims.getIssuedAt().getTime();
            long expiration = claims.getExpiration().getTime();
            long difference = expiration - issuedAt;

            // Assert
            assertEquals(JWT_EXPIRATION, difference);
        }
    }

    // Helper methods

    private SecretKey getSigningKey() {
        byte[] keyBytes = Base64.getDecoder().decode(TEST_SECRET);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    private String generateExpiredToken(String username) {
        Date now = new Date();
        Date pastDate = new Date(now.getTime() - 1000); // 1 second in the past

        return Jwts.builder()
                .subject(username)
                .issuedAt(new Date(now.getTime() - JWT_EXPIRATION - 2000))
                .expiration(pastDate)
                .signWith(getSigningKey())
                .compact();
    }
}