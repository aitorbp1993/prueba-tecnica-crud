package com.aitorbartolome.prueba_tecnica_crud;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.domain.EntityScan;

@EntityScan("com.aitorbartolome.prueba_tecnica_crud.entity")
@SpringBootApplication
public class PruebaTecnicaCrudApplication {

	public static void main(String[] args) {
		SpringApplication.run(PruebaTecnicaCrudApplication.class, args);
	}

}
