package com.aitorbartolome.prueba_tecnica_crud.repository;

import com.aitorbartolome.prueba_tecnica_crud.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;
import java.util.UUID;

/**
 * Repositorio para la entidad User.
 * Al extender JpaRepository, Spring Data JPA nos proporciona automáticamente
 * métodos CRUD básicos (save, findById, findAll, delete, etc.).
 */
@Repository
public interface UserRepository extends JpaRepository<User, UUID> {

    // Spring Data JPA entenderá este método y buscará un usuario por su username
    Optional<User> findByUsername(String username);

    // Métodos optimizados que solo devuelven true/false
    boolean existsByUsername(String username);

    boolean existsByEmail(String email);
}