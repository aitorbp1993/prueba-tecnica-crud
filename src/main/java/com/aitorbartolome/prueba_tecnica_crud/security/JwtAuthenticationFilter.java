package com.aitorbartolome.prueba_tecnica_crud.security;

import com.aitorbartolome.prueba_tecnica_crud.security.constants.JwtConstants;
import com.aitorbartolome.prueba_tecnica_crud.exception.JwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;
import java.util.stream.Collectors;

/**
 * Filtro de autenticación JWT
 * Valida y procesa los tokens JWT en cada petición
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtProvider jwtProvider;
    private final JwtValidator jwtValidator;
    private final UserDetailsService userDetailsService;

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain
    ) throws ServletException, IOException {

        final String authHeader = request.getHeader(JwtConstants.AUTHORIZATION_HEADER);

        // Si no hay header de autorización, deja pasar
        if (authHeader == null || authHeader.isEmpty()) {
            log.debug("No hay header de autorización");
            filterChain.doFilter(request, response);
            return;
        }

        try {
            // Extrae el token del header
            String jwt = jwtValidator.extractBearerToken(authHeader);

            if (jwt == null || jwt.isEmpty()) {
                log.debug("Token Bearer vacío");
                filterChain.doFilter(request, response);
                return;
            }

            // Valida la estructura del token
            jwtProvider.validateTokenStructure(jwt);

            // Extrae el username del token
            String username = jwtProvider.extractUsername(jwt);

            // Si el usuario aún no está autenticado
            if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
                try {
                    // Carga los detalles del usuario
                    UserDetails userDetails = userDetailsService.loadUserByUsername(username);

                    // Valida que el token sea válido para este usuario
                    if (jwtProvider.isTokenValid(jwt, username)) {
                        // Extrae los roles del token
                        List<String> roles = jwtProvider.extractRoles(jwt);
                        List<GrantedAuthority> authorities = roles.stream()
                                .map(SimpleGrantedAuthority::new)
                                .collect(Collectors.toList());

                        // Crea el token de autenticación
                        UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                                userDetails,
                                null,
                                authorities
                        );
                        authToken.setDetails(
                                new WebAuthenticationDetailsSource().buildDetails(request)
                        );

                        // Establece la autenticación en el contexto
                        SecurityContextHolder.getContext().setAuthentication(authToken);
                        log.debug("Usuario autenticado: {} con roles: {}", username, roles);
                    } else {
                        log.warn("Token inválido para usuario: {}", username);
                    }

                } catch (UsernameNotFoundException e) {
                    log.warn("Usuario no encontrado: {}", username);
                    // El usuario no existe, se permite continuar sin autenticar
                }
            }

        } catch (JwtException e) {
            log.warn("Error de validación JWT: {} - {}", e.getErrorCode(), e.getMessage());
            // Las excepciones JWT se capturan pero no rompemos el flujo
            // La autenticación simplemente no se establece
        } catch (Exception e) {
            log.error("Error inesperado en el filtro JWT", e);
            // Cualquier otro error también se captura para no romper el flujo
        }

        // Continúa con el siguiente filtro
        filterChain.doFilter(request, response);
    }
}