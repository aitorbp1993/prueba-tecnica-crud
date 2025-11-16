package com.aitorbartolome.prueba_tecnica_crud.controller;

import com.aitorbartolome.prueba_tecnica_crud.dto.LoginRequestDTO;
import com.aitorbartolome.prueba_tecnica_crud.dto.LoginResponseDTO;
import com.aitorbartolome.prueba_tecnica_crud.dto.RefreshTokenRequestDTO;
import com.aitorbartolome.prueba_tecnica_crud.entity.User;
import com.aitorbartolome.prueba_tecnica_crud.exception.ErrorCode;
import com.aitorbartolome.prueba_tecnica_crud.exception.InvalidTokenException;
import com.aitorbartolome.prueba_tecnica_crud.exception.UnauthorizedException;
import com.aitorbartolome.prueba_tecnica_crud.repository.UserRepository;
import com.aitorbartolome.prueba_tecnica_crud.security.JwtProvider;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.stream.Collectors;

/**
 * The type Auth controller.
 */
@Slf4j
@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
@Tag(name = "Authentication", description = "User authentication and JWT token management endpoints")
public class AuthController {

    private final AuthenticationManager authenticationManager;
    private final JwtProvider jwtProvider;
    private final UserRepository userRepository;

    /**
     * Login response entity.
     *
     * @param request the request
     * @return the response entity
     */
    @Operation(
            summary = "User Login",
            description = "Authenticates user with credentials (username/password) and returns JWT access token and refresh token. " +
                    "The access token is valid for 1 hour and the refresh token for 7 days."
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "Login successful - returns access and refresh tokens",
                    content = @Content(
                            mediaType = "application/json",
                            schema = @Schema(implementation = LoginResponseDTO.class)
                    )
            ),
            @ApiResponse(
                    responseCode = "400",
                    description = "Validation error - missing or empty username/password",
                    content = @Content(mediaType = "application/json")
            ),
            @ApiResponse(
                    responseCode = "401",
                    description = "Unauthorized - invalid username or password",
                    content = @Content(mediaType = "application/json")
            ),
            @ApiResponse(
                    responseCode = "500",
                    description = "Internal server error",
                    content = @Content(mediaType = "application/json")
            )
    })
    @PostMapping("/login")
    public ResponseEntity<LoginResponseDTO> login(
            @Valid @RequestBody LoginRequestDTO request) {
        log.info("Login attempt for user: {}", request.getUsername());

        try {
            // Authenticate user credentials
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            request.getUsername(),
                            request.getPassword()
                    )
            );

            User user = userRepository.findByUsername(request.getUsername())
                    .orElseThrow(() -> {
                        log.warn("User not found: {}", request.getUsername());
                        return new UsernameNotFoundException("User not found");
                    });

            List<String> roles = authentication.getAuthorities().stream()
                    .map(GrantedAuthority::getAuthority)
                    .collect(Collectors.toList());

            log.debug("User roles: {}", roles);

            String accessToken = jwtProvider.generateAccessToken(
                    user.getUsername(),
                    user.getId(),
                    user.getEmail(),
                    roles
            );

            String refreshToken = jwtProvider.generateRefreshToken(
                    user.getUsername(),
                    user.getId()
            );

            log.info("Login successful for user: {} with roles: {}", request.getUsername(), roles);
            return new ResponseEntity<>(
                    new LoginResponseDTO(accessToken, refreshToken),
                    HttpStatus.OK
            );

        } catch (BadCredentialsException ex) {
            log.warn("Bad credentials for user: {}", request.getUsername());
            throw new UnauthorizedException(
                    "Invalid username or password provided",
                    ErrorCode.AUTH_001
            );
        } catch (UsernameNotFoundException ex) {
            log.warn("User not found: {}", request.getUsername());
            throw new UnauthorizedException(
                    "User not found with the provided username",
                    ErrorCode.AUTH_002
            );
        }
    }

    /**
     * Refresh token response entity.
     *
     * @param request the request
     * @return the response entity
     */
    @Operation(
            summary = "Refresh Access Token",
            description = "Generates a new access token using a valid refresh token. " +
                    "Does not require the expired access token, only the refresh token. " +
                    "Use this when access token expires but refresh token is still valid."
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "Token refreshed successfully - returns new tokens",
                    content = @Content(
                            mediaType = "application/json",
                            schema = @Schema(implementation = LoginResponseDTO.class)
                    )
            ),
            @ApiResponse(
                    responseCode = "400",
                    description = "Validation error - refresh token is blank",
                    content = @Content(mediaType = "application/json")
            ),
            @ApiResponse(
                    responseCode = "401",
                    description = "Unauthorized - refresh token expired, invalid, or malformed",
                    content = @Content(mediaType = "application/json")
            ),
            @ApiResponse(
                    responseCode = "500",
                    description = "Internal server error",
                    content = @Content(mediaType = "application/json")
            )
    })
    @PostMapping("/refresh")
    public ResponseEntity<LoginResponseDTO> refreshToken(
            @Valid @RequestBody RefreshTokenRequestDTO request) {
        log.info("Token refresh attempt");

        try {
            jwtProvider.validateTokenStructure(request.getRefreshToken());
            log.debug("Refresh token structure validated");

            String username = jwtProvider.extractUsername(request.getRefreshToken());
            log.debug("Username extracted from refresh token: {}", username);

            User user = userRepository.findByUsername(username)
                    .orElseThrow(() -> {
                        log.warn("User not found during token refresh: {}", username);
                        return new UsernameNotFoundException("User not found");
                    });

            if (!jwtProvider.isRefreshTokenValid(request.getRefreshToken(), username)) {
                log.warn("Invalid refresh token for user: {}", username);
                throw new InvalidTokenException(
                        "Refresh token is invalid or expired",
                        ErrorCode.JWT_001
                );
            }

            List<String> roles = List.of("ROLE_USER");

            String newAccessToken = jwtProvider.generateAccessToken(
                    user.getUsername(),
                    user.getId(),
                    user.getEmail(),
                    roles
            );

            String newRefreshToken = jwtProvider.generateRefreshToken(
                    user.getUsername(),
                    user.getId()
            );

            log.info("Token refreshed successfully for user: {}", username);
            return new ResponseEntity<>(
                    new LoginResponseDTO(newAccessToken, newRefreshToken),
                    HttpStatus.OK
            );

        } catch (com.aitorbartolome.prueba_tecnica_crud.exception.JwtException ex) {
            log.error("JWT validation failed: {}", ex.getMessage());
            throw new InvalidTokenException(
                    ex.getMessage(),
                    ex.getErrorCodeEnum() != null ? ex.getErrorCodeEnum() : ErrorCode.JWT_002
            );
        } catch (UsernameNotFoundException ex) {
            log.warn("User not found during token refresh");
            throw new UnauthorizedException(
                    "User not found",
                    ErrorCode.AUTH_002
            );
        } catch (InvalidTokenException ex) {
            // Re-throw InvalidTokenException as is
            throw ex;
        } catch (Exception ex) {
            log.error("Unexpected error during token refresh", ex);
            throw new InvalidTokenException(
                    "Failed to refresh token: " + ex.getMessage(),
                    ErrorCode.JWT_002
            );
        }
    }
}