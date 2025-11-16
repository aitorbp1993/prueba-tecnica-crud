package com.aitorbartolome.prueba_tecnica_crud;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.domain.EntityScan;

/**
 * The type Prueba tecnica crud application.
 */
@EntityScan("com.aitorbartolome.prueba_tecnica_crud.entity")
@SpringBootApplication
public class PruebaTecnicaCrudApplication {

    /**
     * The entry point of application.
     *
     * @param args the input arguments
     */
    public static void main(String[] args) {
		SpringApplication.run(PruebaTecnicaCrudApplication.class, args);
	}

}
