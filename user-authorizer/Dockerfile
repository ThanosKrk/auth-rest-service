FROM maven:3.6-jdk-8 as build

COPY src /home/app/src
COPY pom.xml /home/app

WORKDIR /home/app

RUN mvn clean install

FROM java:8-jdk-alpine

# We must have run mvn clean install in order jar to be created
COPY --from=build /home/app/target/user-authorizer-0.0.1-SNAPSHOT.jar /usr/local/lib/demo.jar

EXPOSE 9999

ENTRYPOINT ["java","-jar","/usr/local/lib/demo.jar"]
