# Step 1: Build Stage
FROM maven:3.9.6-eclipse-temurin-17 AS build
WORKDIR /app

# Copy the POM first to cache dependencies
COPY pom.xml .

RUN mvn dependency:go-offline -B

COPY src src

RUN mvn package -DskipTests -B

# Step 2: Runtime Stage (Switched to JRE)
FROM eclipse-temurin:17-jre-jammy
WORKDIR /app

# Grab the JAR from the build stage
COPY --from=build /app/target/auth_service-*.jar app.jar

EXPOSE 10010
ENTRYPOINT ["sh", "-c", "java -Xmx256m -jar app.jar --server.port=${PORT:-10010}"]