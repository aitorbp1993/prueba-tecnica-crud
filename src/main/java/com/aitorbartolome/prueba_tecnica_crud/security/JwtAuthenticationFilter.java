package com.aitorbartolome.prueba_tecnica_crud.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtService jwtService;
    private final UserDetailsService userDetailsService;

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain
    ) throws ServletException, IOException {

        final String authHeader = request.getHeader("Authorization");

        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            // 1. No hay token. Deja pasar la petición.
            // (La regla .permitAll() de Swagger funcionará aquí)
            filterChain.doFilter(request, response);
            return;
        }

        // --- ¡AQUÍ ESTÁ LA SOLUCIÓN! ---
        try {
            final String jwt = authHeader.substring(7);
            final String username = jwtService.extractUsername(jwt);

            // Si tenemos username Y el usuario no está ya autenticado...
            if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {

                UserDetails userDetails = this.userDetailsService.loadUserByUsername(username);

                // Si el token es válido...
                if (jwtService.isTokenValid(jwt, userDetails.getUsername())) {
                    // Autenticamos al usuario
                    UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                            userDetails,
                            null,
                            userDetails.getAuthorities()
                    );
                    authToken.setDetails(
                            new WebAuthenticationDetailsSource().buildDetails(request)
                    );
                    SecurityContextHolder.getContext().setAuthentication(authToken);
                }
            }

        } catch (Exception e) {
            // --- ¡EL CAMBIO CLAVE! ---
            // Capturamos CUALQUIER excepción (JwtException, UsernameNotFoundException, etc.)
            // No hacemos nada con ella, simplemente evitamos que el filtro se rompa.
            // Al no autenticar al usuario, la petición continúa "como anónima"
            // y la regla .permitAll() de Swagger podrá (¡por fin!) hacer su trabajo.
        }
        // --- FIN DE LA SOLUCIÓN ---

        // 2. Deja pasar la petición (autenticada o no) al siguiente filtro
        filterChain.doFilter(request, response);
    }
}