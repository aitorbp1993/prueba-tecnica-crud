package com.aitorbartolome.prueba_tecnica_crud.security;

import com.aitorbartolome.prueba_tecnica_crud.exception.JwtException;
import com.aitorbartolome.prueba_tecnica_crud.security.constants.JwtConstants;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import java.io.IOException;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@DisplayName("JwtAuthenticationFilter Tests")
class JwtAuthenticationFilterTest {

    @Mock
    private JwtProvider jwtProvider;

    @Mock
    private JwtValidator jwtValidator;

    @Mock
    private UserDetailsService userDetailsService;

    @Mock
    private HttpServletRequest request;

    @Mock
    private HttpServletResponse response;

    @Mock
    private FilterChain filterChain;

    @Mock
    private SecurityContext securityContext;

    @InjectMocks
    private JwtAuthenticationFilter jwtAuthenticationFilter;

    private static final String VALID_TOKEN = "valid.jwt.token";
    private static final String BEARER_TOKEN = "Bearer " + VALID_TOKEN;
    private static final String TEST_USERNAME = "testuser";
    private static final List<String> TEST_ROLES = Arrays.asList("ROLE_USER", "ROLE_ADMIN");

    @BeforeEach
    void setUp() {
        SecurityContextHolder.clearContext();
        SecurityContextHolder.setContext(securityContext);
    }

    @Nested
    @DisplayName("No Authorization Header Tests")
    class NoAuthorizationHeaderTests {

        @Test
        @DisplayName("Should continue filter chain when authorization header is null")
        void shouldContinueFilterChainWhenAuthorizationHeaderIsNull() throws ServletException, IOException {
            // Arrange
            when(request.getHeader(JwtConstants.AUTHORIZATION_HEADER)).thenReturn(null);

            // Act
            jwtAuthenticationFilter.doFilterInternal(request, response, filterChain);

            // Assert
            verify(filterChain, times(1)).doFilter(request, response);
            verify(jwtValidator, never()).extractBearerToken(anyString());
            verify(jwtProvider, never()).validateTokenStructure(anyString());
        }

        @Test
        @DisplayName("Should continue filter chain when authorization header is empty")
        void shouldContinueFilterChainWhenAuthorizationHeaderIsEmpty() throws ServletException, IOException {
            // Arrange
            when(request.getHeader(JwtConstants.AUTHORIZATION_HEADER)).thenReturn("");

            // Act
            jwtAuthenticationFilter.doFilterInternal(request, response, filterChain);

            // Assert
            verify(filterChain, times(1)).doFilter(request, response);
            verify(jwtValidator, never()).extractBearerToken(anyString());
        }
    }

    @Nested
    @DisplayName("Invalid Bearer Token Tests")
    class InvalidBearerTokenTests {

        @Test
        @DisplayName("Should continue filter chain when extracted token is null")
        void shouldContinueFilterChainWhenExtractedTokenIsNull() throws ServletException, IOException {
            // Arrange
            when(request.getHeader(JwtConstants.AUTHORIZATION_HEADER)).thenReturn(BEARER_TOKEN);
            when(jwtValidator.extractBearerToken(BEARER_TOKEN)).thenReturn(null);

            // Act
            jwtAuthenticationFilter.doFilterInternal(request, response, filterChain);

            // Assert
            verify(filterChain, times(1)).doFilter(request, response);
            verify(jwtProvider, never()).validateTokenStructure(anyString());
        }

        @Test
        @DisplayName("Should continue filter chain when extracted token is empty")
        void shouldContinueFilterChainWhenExtractedTokenIsEmpty() throws ServletException, IOException {
            // Arrange
            when(request.getHeader(JwtConstants.AUTHORIZATION_HEADER)).thenReturn(BEARER_TOKEN);
            when(jwtValidator.extractBearerToken(BEARER_TOKEN)).thenReturn("");

            // Act
            jwtAuthenticationFilter.doFilterInternal(request, response, filterChain);

            // Assert
            verify(filterChain, times(1)).doFilter(request, response);
            verify(jwtProvider, never()).validateTokenStructure(anyString());
        }

        @Test
        @DisplayName("Should handle JwtException from extractBearerToken")
        void shouldHandleJwtExceptionFromExtractBearerToken() throws ServletException, IOException {
            // Arrange
            when(request.getHeader(JwtConstants.AUTHORIZATION_HEADER)).thenReturn("InvalidToken");
            when(jwtValidator.extractBearerToken("InvalidToken"))
                    .thenThrow(new io.jsonwebtoken.JwtException(JwtConstants.ERROR_TOKEN_NOT_BEARER));

            // Act
            jwtAuthenticationFilter.doFilterInternal(request, response, filterChain);

            // Assert
            verify(filterChain, times(1)).doFilter(request, response);
            verify(securityContext, never()).setAuthentication(any());
        }
    }

    @Nested
    @DisplayName("Token Validation Tests")
    class TokenValidationTests {

        @Test
        @DisplayName("Should handle JwtException during token structure validation")
        void shouldHandleJwtExceptionDuringTokenStructureValidation() throws ServletException, IOException {
            // Arrange
            when(request.getHeader(JwtConstants.AUTHORIZATION_HEADER)).thenReturn(BEARER_TOKEN);
            when(jwtValidator.extractBearerToken(BEARER_TOKEN)).thenReturn(VALID_TOKEN);
            doThrow(new JwtException("Invalid token structure", "INVALID_STRUCTURE"))
                    .when(jwtProvider).validateTokenStructure(VALID_TOKEN);

            // Act
            jwtAuthenticationFilter.doFilterInternal(request, response, filterChain);

            // Assert
            verify(filterChain, times(1)).doFilter(request, response);
            verify(jwtProvider, times(1)).validateTokenStructure(VALID_TOKEN);
            verify(securityContext, never()).setAuthentication(any());
        }

        @Test
        @DisplayName("Should handle unexpected exception during token validation")
        void shouldHandleUnexpectedExceptionDuringTokenValidation() throws ServletException, IOException {
            // Arrange
            when(request.getHeader(JwtConstants.AUTHORIZATION_HEADER)).thenReturn(BEARER_TOKEN);
            when(jwtValidator.extractBearerToken(BEARER_TOKEN)).thenReturn(VALID_TOKEN);
            doThrow(new RuntimeException("Unexpected error"))
                    .when(jwtProvider).validateTokenStructure(VALID_TOKEN);

            // Act
            jwtAuthenticationFilter.doFilterInternal(request, response, filterChain);

            // Assert
            verify(filterChain, times(1)).doFilter(request, response);
            verify(securityContext, never()).setAuthentication(any());
        }
    }

    @Nested
    @DisplayName("Successful Authentication Tests")
    class SuccessfulAuthenticationTests {

        @Test
        @DisplayName("Should successfully authenticate user with valid token")
        void shouldSuccessfullyAuthenticateUserWithValidToken() throws ServletException, IOException {
            // Arrange
            UserDetails userDetails = createUserDetails(TEST_USERNAME, TEST_ROLES);

            when(request.getHeader(JwtConstants.AUTHORIZATION_HEADER)).thenReturn(BEARER_TOKEN);
            when(jwtValidator.extractBearerToken(BEARER_TOKEN)).thenReturn(VALID_TOKEN);
            doNothing().when(jwtProvider).validateTokenStructure(VALID_TOKEN);
            when(jwtProvider.extractUsername(VALID_TOKEN)).thenReturn(TEST_USERNAME);
            when(securityContext.getAuthentication()).thenReturn(null);
            when(userDetailsService.loadUserByUsername(TEST_USERNAME)).thenReturn(userDetails);
            when(jwtProvider.isTokenValid(VALID_TOKEN, TEST_USERNAME)).thenReturn(true);
            when(jwtProvider.extractRoles(VALID_TOKEN)).thenReturn(TEST_ROLES);

            // Act
            jwtAuthenticationFilter.doFilterInternal(request, response, filterChain);

            // Assert
            ArgumentCaptor<Authentication> authCaptor = ArgumentCaptor.forClass(Authentication.class);
            verify(securityContext).setAuthentication(authCaptor.capture());
            verify(filterChain, times(1)).doFilter(request, response);

            Authentication capturedAuth = authCaptor.getValue();
            assertNotNull(capturedAuth);
            assertEquals(userDetails, capturedAuth.getPrincipal());
            assertEquals(2, capturedAuth.getAuthorities().size());
        }

        @Test
        @DisplayName("Should authenticate user with single role")
        void shouldAuthenticateUserWithSingleRole() throws ServletException, IOException {
            // Arrange
            List<String> singleRole = Collections.singletonList("ROLE_USER");
            UserDetails userDetails = createUserDetails(TEST_USERNAME, singleRole);

            when(request.getHeader(JwtConstants.AUTHORIZATION_HEADER)).thenReturn(BEARER_TOKEN);
            when(jwtValidator.extractBearerToken(BEARER_TOKEN)).thenReturn(VALID_TOKEN);
            doNothing().when(jwtProvider).validateTokenStructure(VALID_TOKEN);
            when(jwtProvider.extractUsername(VALID_TOKEN)).thenReturn(TEST_USERNAME);
            when(securityContext.getAuthentication()).thenReturn(null);
            when(userDetailsService.loadUserByUsername(TEST_USERNAME)).thenReturn(userDetails);
            when(jwtProvider.isTokenValid(VALID_TOKEN, TEST_USERNAME)).thenReturn(true);
            when(jwtProvider.extractRoles(VALID_TOKEN)).thenReturn(singleRole);

            // Act
            jwtAuthenticationFilter.doFilterInternal(request, response, filterChain);

            // Assert
            ArgumentCaptor<Authentication> authCaptor = ArgumentCaptor.forClass(Authentication.class);
            verify(securityContext).setAuthentication(authCaptor.capture());

            Authentication capturedAuth = authCaptor.getValue();
            assertEquals(1, capturedAuth.getAuthorities().size());
            assertTrue(capturedAuth.getAuthorities().stream()
                    .anyMatch(a -> a.getAuthority().equals("ROLE_USER")));
        }

        @Test
        @DisplayName("Should authenticate user with empty roles list")
        void shouldAuthenticateUserWithEmptyRolesList() throws ServletException, IOException {
            // Arrange
            List<String> emptyRoles = Collections.emptyList();
            UserDetails userDetails = createUserDetails(TEST_USERNAME, emptyRoles);

            when(request.getHeader(JwtConstants.AUTHORIZATION_HEADER)).thenReturn(BEARER_TOKEN);
            when(jwtValidator.extractBearerToken(BEARER_TOKEN)).thenReturn(VALID_TOKEN);
            doNothing().when(jwtProvider).validateTokenStructure(VALID_TOKEN);
            when(jwtProvider.extractUsername(VALID_TOKEN)).thenReturn(TEST_USERNAME);
            when(securityContext.getAuthentication()).thenReturn(null);
            when(userDetailsService.loadUserByUsername(TEST_USERNAME)).thenReturn(userDetails);
            when(jwtProvider.isTokenValid(VALID_TOKEN, TEST_USERNAME)).thenReturn(true);
            when(jwtProvider.extractRoles(VALID_TOKEN)).thenReturn(emptyRoles);

            // Act
            jwtAuthenticationFilter.doFilterInternal(request, response, filterChain);

            // Assert
            ArgumentCaptor<Authentication> authCaptor = ArgumentCaptor.forClass(Authentication.class);
            verify(securityContext).setAuthentication(authCaptor.capture());

            Authentication capturedAuth = authCaptor.getValue();
            assertTrue(capturedAuth.getAuthorities().isEmpty());
        }
    }

    @Nested
    @DisplayName("Authentication Skip Tests")
    class AuthenticationSkipTests {

        @Test
        @DisplayName("Should skip authentication when username is null")
        void shouldSkipAuthenticationWhenUsernameIsNull() throws ServletException, IOException {
            // Arrange
            when(request.getHeader(JwtConstants.AUTHORIZATION_HEADER)).thenReturn(BEARER_TOKEN);
            when(jwtValidator.extractBearerToken(BEARER_TOKEN)).thenReturn(VALID_TOKEN);
            doNothing().when(jwtProvider).validateTokenStructure(VALID_TOKEN);
            when(jwtProvider.extractUsername(VALID_TOKEN)).thenReturn(null);

            // Act
            jwtAuthenticationFilter.doFilterInternal(request, response, filterChain);

            // Assert
            verify(filterChain, times(1)).doFilter(request, response);
            verify(userDetailsService, never()).loadUserByUsername(anyString());
            verify(securityContext, never()).setAuthentication(any());
        }

        @Test
        @DisplayName("Should skip authentication when user is already authenticated")
        void shouldSkipAuthenticationWhenUserIsAlreadyAuthenticated() throws ServletException, IOException {
            // Arrange
            Authentication existingAuth = mock(Authentication.class);

            when(request.getHeader(JwtConstants.AUTHORIZATION_HEADER)).thenReturn(BEARER_TOKEN);
            when(jwtValidator.extractBearerToken(BEARER_TOKEN)).thenReturn(VALID_TOKEN);
            doNothing().when(jwtProvider).validateTokenStructure(VALID_TOKEN);
            when(jwtProvider.extractUsername(VALID_TOKEN)).thenReturn(TEST_USERNAME);
            when(securityContext.getAuthentication()).thenReturn(existingAuth);

            // Act
            jwtAuthenticationFilter.doFilterInternal(request, response, filterChain);

            // Assert
            verify(filterChain, times(1)).doFilter(request, response);
            verify(userDetailsService, never()).loadUserByUsername(anyString());
            verify(securityContext, never()).setAuthentication(any());
        }
    }

    @Nested
    @DisplayName("Invalid Token Tests")
    class InvalidTokenTests {

        @Test
        @DisplayName("Should not authenticate when token is invalid for user")
        void shouldNotAuthenticateWhenTokenIsInvalidForUser() throws ServletException, IOException {
            // Arrange
            UserDetails userDetails = createUserDetails(TEST_USERNAME, TEST_ROLES);

            when(request.getHeader(JwtConstants.AUTHORIZATION_HEADER)).thenReturn(BEARER_TOKEN);
            when(jwtValidator.extractBearerToken(BEARER_TOKEN)).thenReturn(VALID_TOKEN);
            doNothing().when(jwtProvider).validateTokenStructure(VALID_TOKEN);
            when(jwtProvider.extractUsername(VALID_TOKEN)).thenReturn(TEST_USERNAME);
            when(securityContext.getAuthentication()).thenReturn(null);
            when(userDetailsService.loadUserByUsername(TEST_USERNAME)).thenReturn(userDetails);
            when(jwtProvider.isTokenValid(VALID_TOKEN, TEST_USERNAME)).thenReturn(false);

            // Act
            jwtAuthenticationFilter.doFilterInternal(request, response, filterChain);

            // Assert
            verify(filterChain, times(1)).doFilter(request, response);
            verify(securityContext, never()).setAuthentication(any());
        }
    }

    @Nested
    @DisplayName("User Not Found Tests")
    class UserNotFoundTests {

        @Test
        @DisplayName("Should handle UsernameNotFoundException gracefully")
        void shouldHandleUsernameNotFoundExceptionGracefully() throws ServletException, IOException {
            // Arrange
            when(request.getHeader(JwtConstants.AUTHORIZATION_HEADER)).thenReturn(BEARER_TOKEN);
            when(jwtValidator.extractBearerToken(BEARER_TOKEN)).thenReturn(VALID_TOKEN);
            doNothing().when(jwtProvider).validateTokenStructure(VALID_TOKEN);
            when(jwtProvider.extractUsername(VALID_TOKEN)).thenReturn(TEST_USERNAME);
            when(securityContext.getAuthentication()).thenReturn(null);
            when(userDetailsService.loadUserByUsername(TEST_USERNAME))
                    .thenThrow(new UsernameNotFoundException("User not found"));

            // Act
            jwtAuthenticationFilter.doFilterInternal(request, response, filterChain);

            // Assert
            verify(filterChain, times(1)).doFilter(request, response);
            verify(securityContext, never()).setAuthentication(any());
        }
    }

    @Nested
    @DisplayName("Edge Cases and Integration Tests")
    class EdgeCasesTests {

        @Test
        @DisplayName("Should handle different usernames")
        void shouldHandleDifferentUsernames() throws ServletException, IOException {
            // Arrange
            String anotherUsername = "anotheruser";
            UserDetails userDetails = createUserDetails(anotherUsername, TEST_ROLES);

            when(request.getHeader(JwtConstants.AUTHORIZATION_HEADER)).thenReturn(BEARER_TOKEN);
            when(jwtValidator.extractBearerToken(BEARER_TOKEN)).thenReturn(VALID_TOKEN);
            doNothing().when(jwtProvider).validateTokenStructure(VALID_TOKEN);
            when(jwtProvider.extractUsername(VALID_TOKEN)).thenReturn(anotherUsername);
            when(securityContext.getAuthentication()).thenReturn(null);
            when(userDetailsService.loadUserByUsername(anotherUsername)).thenReturn(userDetails);
            when(jwtProvider.isTokenValid(VALID_TOKEN, anotherUsername)).thenReturn(true);
            when(jwtProvider.extractRoles(VALID_TOKEN)).thenReturn(TEST_ROLES);

            // Act
            jwtAuthenticationFilter.doFilterInternal(request, response, filterChain);

            // Assert
            verify(userDetailsService).loadUserByUsername(anotherUsername);
            verify(jwtProvider).isTokenValid(VALID_TOKEN, anotherUsername);
            verify(securityContext).setAuthentication(any());
        }

        @Test
        @DisplayName("Should set authentication details from request")
        void shouldSetAuthenticationDetailsFromRequest() throws ServletException, IOException {
            // Arrange
            UserDetails userDetails = createUserDetails(TEST_USERNAME, TEST_ROLES);

            when(request.getHeader(JwtConstants.AUTHORIZATION_HEADER)).thenReturn(BEARER_TOKEN);
            when(jwtValidator.extractBearerToken(BEARER_TOKEN)).thenReturn(VALID_TOKEN);
            doNothing().when(jwtProvider).validateTokenStructure(VALID_TOKEN);
            when(jwtProvider.extractUsername(VALID_TOKEN)).thenReturn(TEST_USERNAME);
            when(securityContext.getAuthentication()).thenReturn(null);
            when(userDetailsService.loadUserByUsername(TEST_USERNAME)).thenReturn(userDetails);
            when(jwtProvider.isTokenValid(VALID_TOKEN, TEST_USERNAME)).thenReturn(true);
            when(jwtProvider.extractRoles(VALID_TOKEN)).thenReturn(TEST_ROLES);

            // Act
            jwtAuthenticationFilter.doFilterInternal(request, response, filterChain);

            // Assert
            ArgumentCaptor<Authentication> authCaptor = ArgumentCaptor.forClass(Authentication.class);
            verify(securityContext).setAuthentication(authCaptor.capture());

            UsernamePasswordAuthenticationToken capturedAuth =
                    (UsernamePasswordAuthenticationToken) authCaptor.getValue();
            assertNotNull(capturedAuth.getDetails());
        }

        @Test
        @DisplayName("Should verify credentials are null in authentication token")
        void shouldVerifyCredentialsAreNullInAuthenticationToken() throws ServletException, IOException {
            // Arrange
            UserDetails userDetails = createUserDetails(TEST_USERNAME, TEST_ROLES);

            when(request.getHeader(JwtConstants.AUTHORIZATION_HEADER)).thenReturn(BEARER_TOKEN);
            when(jwtValidator.extractBearerToken(BEARER_TOKEN)).thenReturn(VALID_TOKEN);
            doNothing().when(jwtProvider).validateTokenStructure(VALID_TOKEN);
            when(jwtProvider.extractUsername(VALID_TOKEN)).thenReturn(TEST_USERNAME);
            when(securityContext.getAuthentication()).thenReturn(null);
            when(userDetailsService.loadUserByUsername(TEST_USERNAME)).thenReturn(userDetails);
            when(jwtProvider.isTokenValid(VALID_TOKEN, TEST_USERNAME)).thenReturn(true);
            when(jwtProvider.extractRoles(VALID_TOKEN)).thenReturn(TEST_ROLES);

            // Act
            jwtAuthenticationFilter.doFilterInternal(request, response, filterChain);

            // Assert
            ArgumentCaptor<Authentication> authCaptor = ArgumentCaptor.forClass(Authentication.class);
            verify(securityContext).setAuthentication(authCaptor.capture());

            Authentication capturedAuth = authCaptor.getValue();
            assertNull(capturedAuth.getCredentials());
        }

        @Test
        @DisplayName("Should handle multiple roles correctly")
        void shouldHandleMultipleRolesCorrectly() throws ServletException, IOException {
            // Arrange
            List<String> multipleRoles = Arrays.asList("ROLE_USER", "ROLE_ADMIN", "ROLE_MODERATOR");
            UserDetails userDetails = createUserDetails(TEST_USERNAME, multipleRoles);

            when(request.getHeader(JwtConstants.AUTHORIZATION_HEADER)).thenReturn(BEARER_TOKEN);
            when(jwtValidator.extractBearerToken(BEARER_TOKEN)).thenReturn(VALID_TOKEN);
            doNothing().when(jwtProvider).validateTokenStructure(VALID_TOKEN);
            when(jwtProvider.extractUsername(VALID_TOKEN)).thenReturn(TEST_USERNAME);
            when(securityContext.getAuthentication()).thenReturn(null);
            when(userDetailsService.loadUserByUsername(TEST_USERNAME)).thenReturn(userDetails);
            when(jwtProvider.isTokenValid(VALID_TOKEN, TEST_USERNAME)).thenReturn(true);
            when(jwtProvider.extractRoles(VALID_TOKEN)).thenReturn(multipleRoles);

            // Act
            jwtAuthenticationFilter.doFilterInternal(request, response, filterChain);

            // Assert
            ArgumentCaptor<Authentication> authCaptor = ArgumentCaptor.forClass(Authentication.class);
            verify(securityContext).setAuthentication(authCaptor.capture());

            Authentication capturedAuth = authCaptor.getValue();
            assertEquals(3, capturedAuth.getAuthorities().size());
        }

        @Test
        @DisplayName("Should always call filter chain regardless of authentication result")
        void shouldAlwaysCallFilterChainRegardlessOfAuthenticationResult() throws ServletException, IOException {
            // Arrange - invalid token scenario
            when(request.getHeader(JwtConstants.AUTHORIZATION_HEADER)).thenReturn(BEARER_TOKEN);
            when(jwtValidator.extractBearerToken(BEARER_TOKEN)).thenReturn(VALID_TOKEN);
            doThrow(new JwtException("Invalid token", "INVALID"))
                    .when(jwtProvider).validateTokenStructure(VALID_TOKEN);

            // Act
            jwtAuthenticationFilter.doFilterInternal(request, response, filterChain);

            // Assert
            verify(filterChain, times(1)).doFilter(request, response);
        }

        @Test
        @DisplayName("Should verify method call order during successful authentication")
        void shouldVerifyMethodCallOrderDuringSuccessfulAuthentication() throws ServletException, IOException {
            // Arrange
            UserDetails userDetails = createUserDetails(TEST_USERNAME, TEST_ROLES);

            when(request.getHeader(JwtConstants.AUTHORIZATION_HEADER)).thenReturn(BEARER_TOKEN);
            when(jwtValidator.extractBearerToken(BEARER_TOKEN)).thenReturn(VALID_TOKEN);
            doNothing().when(jwtProvider).validateTokenStructure(VALID_TOKEN);
            when(jwtProvider.extractUsername(VALID_TOKEN)).thenReturn(TEST_USERNAME);
            when(securityContext.getAuthentication()).thenReturn(null);
            when(userDetailsService.loadUserByUsername(TEST_USERNAME)).thenReturn(userDetails);
            when(jwtProvider.isTokenValid(VALID_TOKEN, TEST_USERNAME)).thenReturn(true);
            when(jwtProvider.extractRoles(VALID_TOKEN)).thenReturn(TEST_ROLES);

            // Act
            jwtAuthenticationFilter.doFilterInternal(request, response, filterChain);

            // Assert
            var inOrder = inOrder(jwtValidator, jwtProvider, userDetailsService, securityContext, filterChain);
            inOrder.verify(jwtValidator).extractBearerToken(BEARER_TOKEN);
            inOrder.verify(jwtProvider).validateTokenStructure(VALID_TOKEN);
            inOrder.verify(jwtProvider).extractUsername(VALID_TOKEN);
            inOrder.verify(userDetailsService).loadUserByUsername(TEST_USERNAME);
            inOrder.verify(jwtProvider).isTokenValid(VALID_TOKEN, TEST_USERNAME);
            inOrder.verify(jwtProvider).extractRoles(VALID_TOKEN);
            inOrder.verify(securityContext).setAuthentication(any());
            inOrder.verify(filterChain).doFilter(request, response);
        }
    }

    // Helper methods

    private UserDetails createUserDetails(String username, List<String> roles) {
        List<GrantedAuthority> authorities = roles.stream()
                .map(SimpleGrantedAuthority::new)
                .collect(java.util.stream.Collectors.toList());

        return User.builder()
                .username(username)
                .password("password")
                .authorities(authorities)
                .build();
    }
}