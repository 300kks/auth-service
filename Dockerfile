FROM adoptopenjdk/openjdk11
LABEL "Description" = "Auth Service"
COPY target/*.jar auth-service.jar
ENTRYPOINT ["java", "-jar", "/auth-service.jar"]
