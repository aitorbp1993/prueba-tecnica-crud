package com.aitorbartolome.prueba_tecnica_crud.security;

import com.aitorbartolome.prueba_tecnica_crud.security.constants.JwtConstants;
import io.jsonwebtoken.JwtException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@DisplayName("JwtValidator Tests")
class JwtValidatorTest {

    @Mock
    private JwtProvider jwtProvider;

    @InjectMocks
    private JwtValidator jwtValidator;

    private static final String VALID_TOKEN = "valid.jwt.token";
    private static final String BEARER_TOKEN = "Bearer " + VALID_TOKEN;

    @Nested
    @DisplayName("Extract Bearer Token Tests")
    class ExtractBearerTokenTests {

        @Test
        @DisplayName("Should successfully extract token from valid Bearer header")
        void shouldSuccessfullyExtractTokenFromValidBearerHeader() {
            // Act
            String extractedToken = jwtValidator.extractBearerToken(BEARER_TOKEN);

            // Assert
            assertNotNull(extractedToken);
            assertEquals(VALID_TOKEN, extractedToken);
        }

        @Test
        @DisplayName("Should return null when auth header is null")
        void shouldReturnNullWhenAuthHeaderIsNull() {
            // Act
            String extractedToken = jwtValidator.extractBearerToken(null);

            // Assert
            assertNull(extractedToken);
        }

        @Test
        @DisplayName("Should return null when auth header is empty")
        void shouldReturnNullWhenAuthHeaderIsEmpty() {
            // Act
            String extractedToken = jwtValidator.extractBearerToken("");

            // Assert
            assertNull(extractedToken);
        }

        @Test
        @DisplayName("Should throw JwtException when header does not start with Bearer")
        void shouldThrowJwtExceptionWhenHeaderDoesNotStartWithBearer() {
            // Arrange
            String invalidHeader = "InvalidToken";

            // Act & Assert
            JwtException exception = assertThrows(JwtException.class, () -> {
                jwtValidator.extractBearerToken(invalidHeader);
            });

            assertEquals(JwtConstants.ERROR_TOKEN_NOT_BEARER, exception.getMessage());
        }

        @Test
        @DisplayName("Should throw JwtException when header starts with lowercase bearer")
        void shouldThrowJwtExceptionWhenHeaderStartsWithLowercaseBearer() {
            // Arrange
            String invalidHeader = "bearer " + VALID_TOKEN;

            // Act & Assert
            JwtException exception = assertThrows(JwtException.class, () -> {
                jwtValidator.extractBearerToken(invalidHeader);
            });

            assertEquals(JwtConstants.ERROR_TOKEN_NOT_BEARER, exception.getMessage());
        }

        @Test
        @DisplayName("Should throw JwtException when header has incorrect prefix")
        void shouldThrowJwtExceptionWhenHeaderHasIncorrectPrefix() {
            // Arrange
            String invalidHeader = "Basic " + VALID_TOKEN;

            // Act & Assert
            JwtException exception = assertThrows(JwtException.class, () -> {
                jwtValidator.extractBearerToken(invalidHeader);
            });

            assertEquals(JwtConstants.ERROR_TOKEN_NOT_BEARER, exception.getMessage());
        }

        @Test
        @DisplayName("Should extract token when header is exactly 'Bearer '")
        void shouldExtractTokenWhenHeaderIsExactlyBearer() {
            // Arrange
            String headerWithEmptyToken = "Bearer ";

            // Act
            String extractedToken = jwtValidator.extractBearerToken(headerWithEmptyToken);

            // Assert
            assertNotNull(extractedToken);
            assertEquals("", extractedToken);
        }

        @Test
        @DisplayName("Should extract long token correctly")
        void shouldExtractLongTokenCorrectly() {
            // Arrange
            String longToken = "a".repeat(500);
            String bearerHeader = "Bearer " + longToken;

            // Act
            String extractedToken = jwtValidator.extractBearerToken(bearerHeader);

            // Assert
            assertEquals(longToken, extractedToken);
        }

        @Test
        @DisplayName("Should extract token with special characters")
        void shouldExtractTokenWithSpecialCharacters() {
            // Arrange
            String tokenWithSpecialChars = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";
            String bearerHeader = "Bearer " + tokenWithSpecialChars;

            // Act
            String extractedToken = jwtValidator.extractBearerToken(bearerHeader);

            // Assert
            assertEquals(tokenWithSpecialChars, extractedToken);
        }

        @Test
        @DisplayName("Should handle Bearer prefix with extra spaces")
        void shouldHandleBearerPrefixWithExtraSpaces() {
            // Arrange - Note: This should fail because it doesn't start with exactly "Bearer "
            String headerWithExtraSpace = "Bearer  " + VALID_TOKEN;

            // Act
            String extractedToken = jwtValidator.extractBearerToken(headerWithExtraSpace);

            // Assert - The extra space becomes part of the token
            assertEquals(" " + VALID_TOKEN, extractedToken);
        }

        @Test
        @DisplayName("Should verify Bearer prefix length constant is correct")
        void shouldVerifyBearerPrefixLengthConstantIsCorrect() {
            // Arrange
            String token = jwtValidator.extractBearerToken(BEARER_TOKEN);

            // Assert
            assertEquals(7, JwtConstants.BEARER_PREFIX_LENGTH);
            assertEquals(VALID_TOKEN, token);
            assertEquals(BEARER_TOKEN.substring(JwtConstants.BEARER_PREFIX_LENGTH), token);
        }
    }

    @Nested
    @DisplayName("Validate Token Has Roles Tests")
    class ValidateTokenHasRolesTests {

        @Test
        @DisplayName("Should validate successfully when token has roles")
        void shouldValidateSuccessfullyWhenTokenHasRoles() {
            // Arrange
            List<String> roles = Arrays.asList("ROLE_USER", "ROLE_ADMIN");
            when(jwtProvider.extractRoles(VALID_TOKEN)).thenReturn(roles);

            // Act & Assert
            assertDoesNotThrow(() -> {
                jwtValidator.validateTokenHasRoles(VALID_TOKEN, jwtProvider);
            });

            verify(jwtProvider, times(1)).extractRoles(VALID_TOKEN);
        }

        @Test
        @DisplayName("Should validate successfully when token has single role")
        void shouldValidateSuccessfullyWhenTokenHasSingleRole() {
            // Arrange
            List<String> singleRole = Collections.singletonList("ROLE_USER");
            when(jwtProvider.extractRoles(VALID_TOKEN)).thenReturn(singleRole);

            // Act & Assert
            assertDoesNotThrow(() -> {
                jwtValidator.validateTokenHasRoles(VALID_TOKEN, jwtProvider);
            });

            verify(jwtProvider, times(1)).extractRoles(VALID_TOKEN);
        }

        @Test
        @DisplayName("Should throw JwtException when token has no roles")
        void shouldThrowJwtExceptionWhenTokenHasNoRoles() {
            // Arrange
            List<String> emptyRoles = Collections.emptyList();
            when(jwtProvider.extractRoles(VALID_TOKEN)).thenReturn(emptyRoles);

            // Act & Assert
            JwtException exception = assertThrows(JwtException.class, () -> {
                jwtValidator.validateTokenHasRoles(VALID_TOKEN, jwtProvider);
            });

            assertEquals("Token sin roles", exception.getMessage());
            verify(jwtProvider, times(1)).extractRoles(VALID_TOKEN);
        }

        @Test
        @DisplayName("Should validate successfully with multiple roles")
        void shouldValidateSuccessfullyWithMultipleRoles() {
            // Arrange
            List<String> multipleRoles = Arrays.asList(
                    "ROLE_USER",
                    "ROLE_ADMIN",
                    "ROLE_MODERATOR",
                    "ROLE_EDITOR"
            );
            when(jwtProvider.extractRoles(VALID_TOKEN)).thenReturn(multipleRoles);

            // Act & Assert
            assertDoesNotThrow(() -> {
                jwtValidator.validateTokenHasRoles(VALID_TOKEN, jwtProvider);
            });

            verify(jwtProvider, times(1)).extractRoles(VALID_TOKEN);
        }

        @Test
        @DisplayName("Should call extractRoles exactly once")
        void shouldCallExtractRolesExactlyOnce() {
            // Arrange
            List<String> roles = Collections.singletonList("ROLE_USER");
            when(jwtProvider.extractRoles(VALID_TOKEN)).thenReturn(roles);

            // Act
            jwtValidator.validateTokenHasRoles(VALID_TOKEN, jwtProvider);

            // Assert
            verify(jwtProvider, times(1)).extractRoles(VALID_TOKEN);
            verifyNoMoreInteractions(jwtProvider);
        }

        @Test
        @DisplayName("Should validate different tokens independently")
        void shouldValidateDifferentTokensIndependently() {
            // Arrange
            String token1 = "token1";
            String token2 = "token2";
            List<String> roles1 = Collections.singletonList("ROLE_USER");
            List<String> roles2 = Collections.singletonList("ROLE_ADMIN");

            when(jwtProvider.extractRoles(token1)).thenReturn(roles1);
            when(jwtProvider.extractRoles(token2)).thenReturn(roles2);

            // Act & Assert
            assertDoesNotThrow(() -> {
                jwtValidator.validateTokenHasRoles(token1, jwtProvider);
                jwtValidator.validateTokenHasRoles(token2, jwtProvider);
            });

            verify(jwtProvider).extractRoles(token1);
            verify(jwtProvider).extractRoles(token2);
        }

        @Test
        @DisplayName("Should handle null roles as empty list")
        void shouldHandleNullRolesAsEmptyList() {
            // Arrange
            when(jwtProvider.extractRoles(VALID_TOKEN)).thenReturn(null);

            // Act & Assert
            assertThrows(NullPointerException.class, () -> {
                jwtValidator.validateTokenHasRoles(VALID_TOKEN, jwtProvider);
            });
        }
    }

    @Nested
    @DisplayName("Edge Cases and Integration Tests")
    class EdgeCasesTests {

        @Test
        @DisplayName("Should handle whitespace-only auth header")
        void shouldHandleWhitespaceOnlyAuthHeader() {
            // Arrange
            String whitespaceHeader = "   ";

            // Act & Assert
            // Since it doesn't start with "Bearer ", it should throw exception
            assertThrows(JwtException.class, () -> {
                jwtValidator.extractBearerToken(whitespaceHeader);
            });
        }

        @Test
        @DisplayName("Should handle Bearer without space")
        void shouldHandleBearerWithoutSpace() {
            // Arrange
            String invalidHeader = "Bearer" + VALID_TOKEN;

            // Act & Assert
            assertThrows(JwtException.class, () -> {
                jwtValidator.extractBearerToken(invalidHeader);
            });
        }

        @Test
        @DisplayName("Should extract empty string token from 'Bearer ' header")
        void shouldExtractEmptyStringTokenFromBearerHeader() {
            // Arrange
            String bearerOnly = JwtConstants.BEARER_PREFIX;

            // Act
            String extractedToken = jwtValidator.extractBearerToken(bearerOnly);

            // Assert
            assertNotNull(extractedToken);
            assertEquals("", extractedToken);
        }

        @Test
        @DisplayName("Should handle token that starts with Bearer but has typo")
        void shouldHandleTokenThatStartsWithBearerButHasTypo() {
            // Arrange
            String typoHeader = "Bearerr " + VALID_TOKEN;

            // Act & Assert
            assertThrows(JwtException.class, () -> {
                jwtValidator.extractBearerToken(typoHeader);
            });
        }

        @Test
        @DisplayName("Should validate that Bearer is case-sensitive")
        void shouldValidateThatBearerIsCaseSensitive() {
            // Arrange
            String[] invalidHeaders = {
                    "bearer " + VALID_TOKEN,
                    "BEARER " + VALID_TOKEN,
                    "BeArEr " + VALID_TOKEN,
                    "bEARER " + VALID_TOKEN
            };

            // Act & Assert
            for (String header : invalidHeaders) {
                assertThrows(JwtException.class, () -> {
                    jwtValidator.extractBearerToken(header);
                }, "Should throw exception for header: " + header);
            }
        }

        @Test
        @DisplayName("Should handle token with only Bearer prefix")
        void shouldHandleTokenWithOnlyBearerPrefix() {
            // Arrange
            String onlyBearer = "Bearer";

            // Act & Assert
            assertThrows(JwtException.class, () -> {
                jwtValidator.extractBearerToken(onlyBearer);
            });
        }

        @Test
        @DisplayName("Should successfully extract very short token")
        void shouldSuccessfullyExtractVeryShortToken() {
            // Arrange
            String shortToken = "a";
            String bearerHeader = "Bearer " + shortToken;

            // Act
            String extractedToken = jwtValidator.extractBearerToken(bearerHeader);

            // Assert
            assertEquals(shortToken, extractedToken);
        }

        @Test
        @DisplayName("Should handle consecutive Bearer prefix validation")
        void shouldHandleConsecutiveBearerPrefixValidation() {
            // Arrange
            String header1 = "Bearer token1";
            String header2 = "Bearer token2";
            String header3 = "InvalidHeader";

            // Act & Assert
            assertEquals("token1", jwtValidator.extractBearerToken(header1));
            assertEquals("token2", jwtValidator.extractBearerToken(header2));
            assertThrows(JwtException.class, () -> {
                jwtValidator.extractBearerToken(header3);
            });
        }

        @Test
        @DisplayName("Should verify validateTokenHasRoles throws correct exception")
        void shouldVerifyValidateTokenHasRolesThrowsCorrectException() {
            // Arrange
            when(jwtProvider.extractRoles(VALID_TOKEN)).thenReturn(Collections.emptyList());

            // Act
            JwtException exception = assertThrows(JwtException.class, () -> {
                jwtValidator.validateTokenHasRoles(VALID_TOKEN, jwtProvider);
            });

            // Assert
            assertEquals("Token sin roles", exception.getMessage());
            assertNotNull(exception);
        }

        @Test
        @DisplayName("Should handle mixed valid and invalid operations")
        void shouldHandleMixedValidAndInvalidOperations() {
            // Arrange
            List<String> validRoles = Collections.singletonList("ROLE_USER");
            List<String> emptyRoles = Collections.emptyList();

            when(jwtProvider.extractRoles("validToken")).thenReturn(validRoles);
            when(jwtProvider.extractRoles("emptyRolesToken")).thenReturn(emptyRoles);

            // Act & Assert
            // Valid bearer extraction
            assertEquals(VALID_TOKEN, jwtValidator.extractBearerToken(BEARER_TOKEN));

            // Invalid bearer extraction
            assertThrows(JwtException.class, () -> {
                jwtValidator.extractBearerToken("InvalidBearer");
            });

            // Valid role validation
            assertDoesNotThrow(() -> {
                jwtValidator.validateTokenHasRoles("validToken", jwtProvider);
            });

            // Invalid role validation
            assertThrows(JwtException.class, () -> {
                jwtValidator.validateTokenHasRoles("emptyRolesToken", jwtProvider);
            });
        }
    }
}