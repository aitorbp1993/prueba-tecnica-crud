# Etapa de build (compila el proyecto con Maven dentro del contenedor)
FROM maven:3.9.9-eclipse-temurin-17 AS build
WORKDIR /app

# Copiamos primero el pom.xml y resolvemos dependencias para cachear mejor
COPY pom.xml .
RUN mvn -q -DskipTests dependency:go-offline

# Copiamos el código y construimos el JAR
COPY src ./src
RUN mvn -q -DskipTests clean package

# Etapa de runtime (imagen ligera con JRE 17)
FROM eclipse-temurin:17-jre-alpine
WORKDIR /app

# Variables opcionales (puedes sobreescribirlas al ejecutar)
ENV JAVA_OPTS=""
ENV SPRING_PROFILES_ACTIVE=default

# Exponemos el puerto por el que escucha Spring Boot
EXPOSE 8080

# Copiamos el JAR construido en la etapa anterior
# Si target tiene un único .jar, esto lo cogerá correctamente
COPY --from=build /app/target/*.jar /app/app.jar

# Comando de arranque
ENTRYPOINT ["sh", "-c", "java $JAVA_OPTS -jar /app/app.jar"]