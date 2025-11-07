# --- Stage 1: Build Stage ---
# Use an official OpenJDK 17 image as the base
# This image includes Maven and the full JDK
FROM eclipse-temurin:17-jdk-jammy AS build

# Set the working directory inside the container
WORKDIR /workspace

# Copy the Maven wrapper files and the pom.xml
# We copy these first to leverage Docker's layer caching.
# If these files don't change, Docker won't re-download dependencies.
COPY mvnw .
COPY .mvn .mvn
COPY pom.xml .

# Copy the rest of your project's source code
COPY src src

# Make the Maven wrapper executable
RUN chmod +x mvnw

# Build the application and skip tests
# This creates the .jar file in the /workspace/target/ directory
RUN ./mvnw clean install -DskipTests

# --- Stage 2: Run Stage ---
# Use a minimal JRE 17 image for the final container
# This results in a much smaller image than the full JDK
FROM eclipse-temurin:17-jre-jammy

# Set the working directory for the app
WORKDIR /app

# NEW: Copy the krb5.conf file from the build context into the final image
COPY src/main/resources/krb5.conf /etc/krb5.conf

# Copy the executable .jar file from the 'build' stage
# The JAR name comes from the <artifactId> and <version> in your pom.xml
COPY --from=build /workspace/target/sso-auth-system-1.0.0.jar .

# Expose the port your application runs on
# This is specified in your application.properties
EXPOSE 8080

# The command to run your application when the container starts
ENTRYPOINT ["java", "-jar", "sso-auth-system-1.0.0.jar"]