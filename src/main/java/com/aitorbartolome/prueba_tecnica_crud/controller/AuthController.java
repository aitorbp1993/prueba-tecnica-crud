package com.aitorbartolome.prueba_tecnica_crud.controller;

import com.aitorbartolome.prueba_tecnica_crud.dto.LoginRequestDTO;
import com.aitorbartolome.prueba_tecnica_crud.dto.LoginResponseDTO;
import com.aitorbartolome.prueba_tecnica_crud.security.JwtService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;


@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
@Tag(name = "Autenticación", description = "Endpoint para el login de usuarios.")
public class AuthController {

    private final AuthenticationManager authenticationManager;
    private final JwtService jwtService;


    @Operation(summary = "Inicia sesión y obtiene un token JWT",
            description = "Valida las credenciales y, si son correctas, " +
                    "devuelve un token JWT para usar en endpoints protegidos.")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Login exitoso, devuelve token"),
            @ApiResponse(responseCode = "400", description = "Error de validación (campos vacíos)"),
            @ApiResponse(responseCode = "401", description = "Credenciales incorrectas (Unauthorized)")
    })
    @PostMapping("/login")
    public ResponseEntity<LoginResponseDTO> login(
            @Valid @RequestBody LoginRequestDTO request) {
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getUsername(),
                        request.getPassword()
                )
        );

        String jwtToken = jwtService.generateToken(request.getUsername());

        return ResponseEntity.ok(new LoginResponseDTO(jwtToken));
    }
}