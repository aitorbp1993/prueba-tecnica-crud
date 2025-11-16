# Prueba Técnica Backend · Gestión de Usuarios y Autenticación (Spring Boot)

API REST en Java (Spring Boot 3) para gestionar usuarios y realizar un inicio de sesión básico.

Índice
- 1. Qué hace la API
- 2. Stack técnico
- 3. Cómo ejecutar
- 4. Configuración (propiedades y variables de entorno)
- 5. Modelo de datos
- 6. Endpoints y ejemplos (curl)
- 7. Validaciones y reglas de negocio
- 8. Seguridad (JWT)
- 9. Persistencia y consola H2
- 10. Manejo de errores (formato de respuesta)
- 11. Tests
- 12. Decisiones técnicas y cómo escalar
- 13. Estructura del proyecto

---

## 1) Qué hace la API

Funciones principales:
- Crear usuario
- Listar usuarios
- Consultar usuario por id
- Eliminar usuario
- Iniciar sesión (login con usuario/contraseña) y obtener un token JWT para acceder a endpoints protegidos

Requisitos que cumple:
- Contraseñas almacenadas de forma segura (hash)
- Username y email únicos
- Longitud mínima de contraseña
- Persistencia en H2
- Documentación de uso y ejemplos de prueba (curl)

Extras:
- Swagger
- Manejo estandarizado de errores
- Posibilidad de ejecución en Docker (Dockerfile)

---

## 2) Stack técnico

- Java 17+
- Spring Boot 3.x
  - Spring Web (REST)
  - Spring Data JPA (repositorios)
  - Spring Security (autenticación/autorización)
- JWT (token de acceso)
- H2 (base de datos embebida)
- Lombok (reducción de boilerplate)
- MapStruct (mapeo entre Entidad y DTO)
- Maven

---

## 3) Cómo ejecutar

Requisitos:
- Java 17+
- Maven 3.9+

Opción A. Maven (rápida en local)
```bash
mvn clean spring-boot:run
```

Opción B. JAR
```bash
mvn clean package
java -jar target/*.jar
```

Opción C. Docker (build y run por comandos)
```bash
# construir imagen
docker build -t crud-api:latest .

# ejecutar contenedor (puerto 8080)
docker run --rm -p 8080:8080 --name crud-api crud-api:latest
```

Comprobaciones rápidas:
- Swagger UI : http://localhost:8080/swagger-ui.html
- Consola H2: http://localhost:8080/h2-console (ver sección 9)

---

## 4) Configuración (propiedades y variables de entorno)

Las principales propiedades (application.yml) y sus equivalentes en variables de entorno:

- Base de datos H2 (modo fichero persistente en desarrollo):
  - spring.datasource.url = jdbc:h2:file:./pruebadb
  - spring.datasource.username = sa
  - spring.datasource.password = (vacío)
- H2 Console:
  - spring.h2.console.enabled = true
  - spring.h2.console.path = /h2-console
  - Opcional para acceso desde fuera del proceso (p. ej., Docker):
    - spring.h2.console.settings.web-allow-others = true
- JPA:
  - spring.jpa.hibernate.ddl-auto = update
- JWT:
  - jwt.secret = ${JWT_SECRET:...valor_por_defecto...}
  - jwt.expiration = 3600000 (ms)
  - jwt.refresh-expiration = 604800000 (ms)

---

## 5) Modelo de datos

Entidad: User
- id (UUID) – generado
- username (String) – único, requerido
- email (String) – único, requerido
- password (String) – hash seguro, requerido
- creationDate (LocalDateTime) – fecha de creación (auto-asignada en persistencia)

Nota: La fecha de creación se inicializa automáticamente antes de insertar (ciclo de vida JPA), por lo que está disponible inmediatamente en la respuesta tras crear el usuario.

---

## 6) Endpoints y ejemplos (curl)

Base URL por defecto: http://localhost:8080

- Crear usuario (público)
  - POST /api/v1/users
  - Body:
    ```json
    {
      "username": "aitor",
      "email": "aitor@example.com",
      "password": "Aitor123!"
    }
    ```
  - Ejemplo:
    ```bash
    curl -X POST http://localhost:8080/api/v1/users \
      -H "Content-Type: application/json" \
      -d '{"username":"aitor","email":"aitor@example.com","password":"Aitor123!"}'
    ```

- Login (público)
  - POST /api/v1/auth/login
  - Body:
    ```json
    {
      "username": "aitor",
      "password": "Aitor123!"
    }
    ```
  - Respuesta (ejemplo):
    ```json
    {
      "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
      "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
      "token_type": "Bearer",
      "expires_in": 3600
    }
    ```
  - Ejemplo:
    ```bash
    curl -s -X POST http://localhost:8080/api/v1/auth/login \
      -H "Content-Type: application/json" \
      -d '{"username":"aitor","password":"Aitor123!"}'
    ```

- Refrescar token (público)
  - POST /api/v1/auth/refresh
  - Body:
    ```json
    {
      "refresh_token": "<REFRESH_TOKEN>"
    }
    ```
  - Respuesta (ejemplo):
    ```json
    {
      "access_token": "nuevo_access_token...",
      "token_type": "Bearer",
      "expires_in": 3600
    }
    ```
  - Ejemplo:
    ```bash
    curl -s -X POST http://localhost:8080/api/v1/auth/refresh \
      -H "Content-Type: application/json" \
      -d '{"refresh_token":"<REFRESH_TOKEN>"}'
    ```

- Listar usuarios (protegido)
  - GET /api/v1/users
  - Header: Authorization: Bearer <ACCESS_TOKEN>
  - Ejemplo:
    ```bash
    ACCESS=$(curl -s -X POST http://localhost:8080/api/v1/auth/login \
      -H "Content-Type: application/json" \
      -d '{"username":"aitor","password":"Aitor123!"}' | jq -r '.access_token')

    curl -X GET http://localhost:8080/api/v1/users \
      -H "Authorization: Bearer ${ACCESS}"
    ```

- Obtener usuario por id (protegido)
  - GET /api/v1/users/{id}
  - Ejemplo:
    ```bash
    curl -X GET http://localhost:8080/api/v1/users/<UUID> \
      -H "Authorization: Bearer ${ACCESS}"
    ```

- Eliminar usuario (protegido)
  - DELETE /api/v1/users/{id}
  - Ejemplo:
    ```bash
    curl -X DELETE http://localhost:8080/api/v1/users/<UUID> \
      -H "Authorization: Bearer ${ACCESS}"
    ```
---

## 7) Validaciones y reglas de negocio

- Username:
  - Requerido, 3–50 caracteres
  - Solo letras, números, guion y guion bajo
  - Único (no se permiten duplicados)
- Email:
  - Requerido, formato válido
  - Único
- Password:
  - Requerida, mínimo 8 caracteres
  - Almacenada con hash seguro (p. ej., BCrypt)
  - Se aplican validaciones de robustez (p. ej., mayúscula, dígitos, etc.)

Manejo de duplicados:
- Si un username o email ya existen, la API responde con 409 (Conflict) y mensaje de error.

---

## 8) Seguridad (JWT)

- Autenticación basada en token JWT (Bearer).
- Flujo:
  1) El usuario se registra (POST /users).
  2) Inicia sesión (POST /auth/login) con username y password.
  3) La API devuelve un `access_token` y un `refresh_token`.
  4) Para acceder a endpoints protegidos, incluir `Authorization: Bearer <access_token>`.
  5) Cuando el `access_token` caduque, el cliente puede solicitar uno nuevo con `POST /auth/refresh` enviando el `refresh_token`.
- Hash de contraseñas:
  - Se usa un algoritmo seguro (p. ej., BCrypt). Nunca se devuelve la contraseña.
- Renovación de token (refresh):
  - El `refresh_token` tiene mayor vigencia que el access token (configurable).
  - Debe almacenarse de forma segura por el cliente y no enviarse salvo a `/auth/refresh`.
  - La API puede rotar el refresh token (si está implementado). Si se rota, la respuesta incluirá un nuevo `refresh_token`.

Buenas prácticas:
- Usar un secreto JWT distinto por entorno (no subirlo a repositorios).
- Ajustar caducidades según criticidad (expiración corta para access tokens).
- Si se rota el refresh token, invalidar el anterior (lista de revocación) en escenarios más avanzados.

---

## 9) Persistencia y consola H2

- Consola H2 (solo desarrollo):
  - URL: http://localhost:8080/h2-console
  - JDBC URL: `jdbc:h2:file:./pruebadb`
  - User: `sa`
  - Password: (vacío)
  - Nota: Para acceder a la consola desde fuera del proceso (p. ej., en contenedor), debe estar activado `spring.h2.console.settings.web-allow-others=true`. No activar en producción.

- Producción (visión):
  - Sustituir H2 por una base de datos relacional gestionada y consistente (p. ej., una base SQL gestionada).

---

## 10) Manejo de errores (formato de respuesta)

Formato JSON consistente para errores (ejemplo):
```json
{
  "timestamp": "2025-11-16T11:05:00Z",
  "status": 409,
  "error": "CONFLICT",
  "code": "USER_002",
  "message": "Username 'alice' already exists",
  "path": "/api/v1/users"
}
```

Convenciones típicas:
- 400 Bad Request: validaciones de entrada
- 401 Unauthorized: token ausente o inválido
- 403 Forbidden: sin permisos
- 404 Not Found: recurso no encontrado
- 409 Conflict: duplicados (username/email)
- 500 Internal Server Error: errores no controlados

---

## 11) Tests

Ejecución:
```bash
mvn test
```
---

## 12) Decisiones técnicas y cómo escalar

Decisiones:
- Arquitectura en capas (Controller → Service → Repository → Mapper → DTO) para separar responsabilidades y evitar exponer entidades.
- DTOs para entrada/salida: evitan filtrar campos sensibles (password) y facilitan cambios de contrato.
- Hash de contraseñas: se utiliza un algoritmo seguro estándar.
- JWT: elección pragmática y habitual para APIs stateless; facilita integrar roles y refresh token.
- H2 en fichero para desarrollo: persistencia local sin infraestructura adicional.

Escalabilidad futura:
- Sustituir H2 por una base de datos relacional gestionada y consistente (servicio SQL administrado).
- Incorporar migraciones de esquema controladas.
- Añadir roles/permisos (claims en JWT, capa de autorización más granular).
- Paginación y filtros en listados (page/size/sort).
- Observabilidad: métricas/health/logs estructurados.
- Pruebas con Testcontainers y pipelines CI/CD.

---

## 13) Estructura del proyecto

Ejemplo de estructura (resumen):
```
src/
  main/
    java/com/aitorbartolome/prueba_tecnica_crud/
      controller/        # REST Controllers
      service/           # Interfaces y servicios
      service/impl/      # Implementaciones
      repository/        # Spring Data JPA repos
      entity/            # Entidades JPA (User)
      dto/               # DTOs de request/response
      mapper/            # MapStruct mappers
      security/          # Config y filtros de seguridad (JWT)
      exception/         # Manejo global de errores y códigos
      config/            # Configuración de app
    resources/
      application.yml    # Propiedades de la app
  test/                  # Tests unitarios e integración
Dockerfile               # (opcional) build y run en contenedor
```

---

## Anexo: Colección de Postman y diagrama de autenticación

Colección de Postman:
- Archivo: `postman/PruebaTecnicaCRUD.postman_collection.json`
- Instrucciones:
  1) Importa ambos archivos en Postman.
  2) Selecciona el entorno “Local”.
  3) Ejecuta en este orden: “Users - Create”, “Auth - Login”, “Users - List”.  
     Los scripts de la colección guardan automáticamente `access_token` y `refresh_token`.  
     Cuando el access token caduque, usa “Auth - Refresh” para obtener uno nuevo.

