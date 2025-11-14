package com.aitorbartolome.prueba_tecnica_crud.config;

import com.aitorbartolome.prueba_tecnica_crud.security.JwtAuthenticationFilter;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
// ¡¡Este import es NUEVO y CLAVE!!
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import static org.springframework.boot.autoconfigure.security.servlet.PathRequest.toH2Console;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final JwtAuthenticationFilter jwtAuthFilter;

    /**
     * BEAN 1: El Cortafuegos (LA SOLUCIÓN AL 403)
     *
     * Aquí le decimos a Spring Security que IGNORE por completo estas rutas.
     * No se ejecutará ningún filtro (ni JWT, ni CSRF) sobre ellas.
     * Es la forma correcta de exponer assets estáticos y consolas de BBDD.
     */
    @Bean
    public WebSecurityCustomizer webSecurityCustomizer() {
        return (web) -> web.ignoring()
                .requestMatchers("/v3/api-docs/**")
                .requestMatchers("/swagger-ui/**")
                .requestMatchers(toH2Console());
    }

    /**
     * BEAN 2: La Cadena de Filtros (Solo para la API)
     *
     * Esta cadena SÍ ejecutará los filtros (como JwtAuthenticationFilter)
     * pero solo para las rutas que NO estén en la lista "ignoring".
     */
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf(csrf -> csrf.disable()) // Deshabilita CSRF


                .authorizeHttpRequests(auth -> auth
                        // Reglas de la API
                        .requestMatchers("/api/v1/auth/**").permitAll()
                        .requestMatchers(HttpMethod.POST, "/api/v1/users").permitAll()

                        // (Hemos quitado Swagger y H2 de aquí, ya están en el 'ignoring')

                        // Todo lo demás, protegido
                        .anyRequest().authenticated()
                )
                .sessionManagement(session -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                )
                .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }
}