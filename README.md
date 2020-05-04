Example Custom Authenticator
===================================================

1. First, Keycloak must be running. 

2. Execute the follow.  This will build the example and deploy it

   `mvn clean install`
   
3. Copy the built artifact from target into the running keycloak container, to the path `/opt/jboss/keycloak/standalone/deployments` within the container. For eg.

    `docker cp target/keycloak-otp-authenticator-jar-with-dependencies.jar {{CONTAINER-ID}}:/opt/jboss/keycloak/standalone/deployments`
    
4. Watch the logs to check the status of the deploy.

