package org.keycloak.examples.authenticator;

import com.fasterxml.jackson.databind.ObjectMapper;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserProvider;
import org.keycloak.representations.idm.OAuth2ErrorRepresentation;

import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;
import java.io.IOException;
import java.util.AbstractMap;
import java.util.HashMap;


public class OtpAuthenticator implements Authenticator {
    OkHttpClient client = new OkHttpClient().newBuilder().build();

    public Response errorResponse(int status, String error, String errorDescription) {
        OAuth2ErrorRepresentation errorRep = new OAuth2ErrorRepresentation(error, errorDescription);
        return Response.status(status).entity(errorRep).type(MediaType.APPLICATION_JSON_TYPE).build();
    }

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        MultivaluedMap<String, String> decodedFormParameters = context.getHttpRequest().getDecodedFormParameters();
        String otp = decodedFormParameters.getFirst("otp");
        String sessionId = decodedFormParameters.getFirst("session_id");
        if((otp == null || otp.isEmpty()) || (sessionId==null || sessionId.isEmpty()) ) {
            context.attempted();
            return;
        }
        AbstractMap.SimpleEntry<String, Boolean> validationEntry = validateOtp(context);
        UserProvider userProvider = context.getSession().users();
        String username = decodedFormParameters.getFirst("username");
        context.setUser(userProvider.getUserByUsername(username, context.getRealm()));
        if (!validationEntry.getValue()) {
            ObjectMapper objectMapper = new ObjectMapper();
            Response response;
            try {
                HashMap jsonObject = objectMapper.readValue(validationEntry.getKey().getBytes(), HashMap.class);
                response =  errorResponse(Response.Status.UNAUTHORIZED.getStatusCode(),jsonObject.get("responseType").toString(),jsonObject.get("message").toString());
            } catch (IOException e) {
                e.printStackTrace();
                response = errorResponse(Response.Status.UNAUTHORIZED.getStatusCode(),"Invalid OTP", "Invalid OTP");
            }
            context.failure(AuthenticationFlowError.INVALID_CREDENTIALS, response);
            return;
        }
        context.success();
    }

    @Override
    public void action(AuthenticationFlowContext context) {
    }

    protected AbstractMap.SimpleEntry<String, Boolean> validateOtp(AuthenticationFlowContext context) {
        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
        String otp = formData.getFirst("otp");
        String sessionId = formData.getFirst("session_id");
        RequestBody body = RequestBody.create(okhttp3.MediaType.parse("application/json"),String.format( "{\"value\" : \"%s\"}",otp));

        String otpHost = context.getAuthenticatorConfig().getConfig().get("otp.hostname");
        String otpPort = context.getAuthenticatorConfig().getConfig().get("otp.port");
        String otpRequestUrl = String.format("http://%s",otpHost);
        if (!otpPort.isEmpty()) {
            otpRequestUrl = String.format("%s:%s",otpRequestUrl,otpPort);
        }
        Request request = new Request.Builder()
                .url(String.format("%s/otp/%s/verify", otpRequestUrl, sessionId))
                .method("POST", body)
                .addHeader("Content-Type", "application/json")
                .build();
        try {
            okhttp3.Response response = client.newCall(request).execute();
            String responseBody = response.body().string();
            return new AbstractMap.SimpleEntry<>(responseBody, response.code() == 200);
        } catch (IOException e) {
            return new AbstractMap.SimpleEntry<>("", false);
        }
    }

    @Override
    public boolean requiresUser() {
        return false;
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        return true;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
    }

    @Override
    public void close() {

    }
}
