package com.aitorbartolome.prueba_tecnica_crud.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration // Le dice a Spring que esta clase contiene configuraciones (Beans)
public class SecurityConfig {

    /**
     * Define un Bean de PasswordEncoder.
     * Usamos BCrypt, que es el estándar de la industria para hashear contraseñas.
     * Este Bean estará disponible en toda la aplicación para ser inyectado.
     */
    @Bean // Le dice a Spring que este método crea un objeto que debe gestionar
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}