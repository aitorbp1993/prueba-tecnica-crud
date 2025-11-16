package com.aitorbartolome.prueba_tecnica_crud.config;

import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Contact;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.info.License;
import io.swagger.v3.oas.models.security.SecurityRequirement;
import io.swagger.v3.oas.models.security.SecurityScheme;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * The type Open api config.
 */
@Configuration
public class OpenApiConfig {

    /**
     * Custom open api open api.
     *
     * @return the open api
     */
    @Bean
    public OpenAPI customOpenAPI() {

        final String securitySchemeName = "bearerAuth";
        SecurityScheme securityScheme = new SecurityScheme()
                .name(securitySchemeName)
                .type(SecurityScheme.Type.HTTP)
                .scheme("bearer")
                .bearerFormat("JWT")
                .in(SecurityScheme.In.HEADER)
                .description("Introduce tu token JWT (obtenido en /auth/login) aquí.");

        Info info = new Info()
                .title("API REST - Prueba Técnica Backend")
                .version("1.0.0")
                .description("API para la gestión de usuarios y autenticación, " +
                        "creada con Spring Boot y securizada con JWT.")
                .contact(new Contact()
                        .name("Aitor Bartolomé")
                        .email("aitor.tsf@gmail.com"));

        return new OpenAPI()
                .info(info)
                .addSecurityItem(new SecurityRequirement()
                        .addList(securitySchemeName))
                .components(new Components()
                        .addSecuritySchemes(securitySchemeName, securityScheme));
    }
}