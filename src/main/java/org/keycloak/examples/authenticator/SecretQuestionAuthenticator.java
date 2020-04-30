/*
 * Copyright 2016 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.keycloak.examples.authenticator;

import com.google.common.base.Function;
import com.google.zxing.common.StringUtils;
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

import javax.ws.rs.core.Cookie;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;
import java.io.IOException;


/**
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @version $Revision: 1 $
 */
public class SecretQuestionAuthenticator implements Authenticator {
    OkHttpClient client = new OkHttpClient().newBuilder().build();

    protected boolean hasCookie(AuthenticationFlowContext context) {
        Cookie cookie = context.getHttpRequest().getHttpHeaders().getCookies().get("SECRET_QUESTION_ANSWERED");
        boolean result = cookie != null;
        if (result) {
            System.out.println("Bypassing secret question because cookie is set");
        }
        return result;
    }

    public Response errorResponse(int status, String error, String errorDescription) {
        OAuth2ErrorRepresentation errorRep = new OAuth2ErrorRepresentation(error, errorDescription);
        return Response.status(status).entity(errorRep).type(MediaType.APPLICATION_JSON_TYPE).build();
    }

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        System.out.println("Inside authenticate : new code");
        boolean validated = validateOtp(context);
        UserProvider userProvider = context.getSession().users();
        MultivaluedMap<String, String> decodedFormParameters = context.getHttpRequest().getDecodedFormParameters();
        String username = decodedFormParameters.getFirst("username");
        System.out.println(String.format("username : %s",username));
        context.setUser(userProvider.getUserByUsername(username, context.getRealm()));
        if (!validated) {
            Response challengeResponse = errorResponse(Response.Status.UNAUTHORIZED.getStatusCode(), "invalid_otp", "Invalid otp");
            context.failure(AuthenticationFlowError.INVALID_CREDENTIALS, challengeResponse );
            context.attempted();
            return;
        }
        System.out.println("Validation success");
//        InMemoryUserAdapter user = new InMemoryUserAdapter(context.getSession(), context.getRealm(), username);
        context.attempted();
//        context.setUser();
        context.success();
    }

    @Override
    public void action(AuthenticationFlowContext context) {
    }

    protected boolean validateOtp(AuthenticationFlowContext context) {
        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
        String otp = formData.getFirst("otp");
        String sessionId = formData.getFirst("session_id");
        if((otp == null || otp.isEmpty()) || (sessionId==null || sessionId.isEmpty()) ) {
            return false;
        }
        RequestBody body = RequestBody.create(okhttp3.MediaType.parse("application/json"),String.format( "{\"value\" : \"%s\"}",otp));

        String otpHost = context.getAuthenticatorConfig().getConfig().get("otp.hostname");
        System.out.println(String.format("otphost is %s",otpHost));
        String otpPort = context.getAuthenticatorConfig().getConfig().get("otp.port");
        System.out.println(String.format("otpport is %s",otpPort));
        String otpRequestUrl = String.format("http://%s",otpHost);
        if (!otpPort.isEmpty()) {
            otpRequestUrl = String.format("%s:%s",otpRequestUrl,otpPort);
        }
        System.out.println(String.format("formed otprequesturl is %s",otpRequestUrl));
        Request request = new Request.Builder()
                .url(String.format("%s/otp/%s/verify", otpRequestUrl, sessionId))
                .method("POST", body)
                .addHeader("Content-Type", "application/json")
                .build();
        try {
            okhttp3.Response response = client.newCall(request).execute();
            System.out.println(String.format("Status: %s",response.code()));
            System.out.println(response.body().string());
            if (response.code() == 200) {
                return true;
            }
            return false;
        } catch (IOException e) {
            e.printStackTrace();
            return false;
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
//        user.addRequiredAction(SecretQuestionRequiredAction.PROVIDER_ID);
    }

    @Override
    public void close() {

    }
}
