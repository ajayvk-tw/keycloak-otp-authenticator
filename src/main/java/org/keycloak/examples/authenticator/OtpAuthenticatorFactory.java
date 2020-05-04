package org.keycloak.examples.authenticator;

import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.authentication.ConfigurableAuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.ArrayList;
import java.util.List;

/**
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @version $Revision: 1 $
 */
public class OtpAuthenticatorFactory implements AuthenticatorFactory, ConfigurableAuthenticatorFactory {

    public static final String PROVIDER_ID = "keycloak-otp-authenticator";
    private static final OtpAuthenticator SINGLETON = new OtpAuthenticator();

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public Authenticator create(KeycloakSession session) {
        return SINGLETON;
    }

    private static AuthenticationExecutionModel.Requirement[] REQUIREMENT_CHOICES = {
            AuthenticationExecutionModel.Requirement.REQUIRED,
            AuthenticationExecutionModel.Requirement.ALTERNATIVE,
            AuthenticationExecutionModel.Requirement.CONDITIONAL,
            AuthenticationExecutionModel.Requirement.DISABLED
    };
    @Override
    public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return REQUIREMENT_CHOICES;
    }

    @Override
    public boolean isUserSetupAllowed() {
        return true;
    }

    @Override
    public boolean isConfigurable() {
        return true;
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return configProperties;
    }

    private static final List<ProviderConfigProperty> configProperties = new ArrayList<ProviderConfigProperty>();

    static {
        ProviderConfigProperty otpServiceHost;
        otpServiceHost = new ProviderConfigProperty();
        otpServiceHost.setName("otp.hostname");
        otpServiceHost.setLabel("Otp service hostname");
        otpServiceHost.setType(ProviderConfigProperty.STRING_TYPE);
        otpServiceHost.setHelpText("Otp service hostname");
        otpServiceHost.setDefaultValue("otp");
        ProviderConfigProperty otpServicePort;
        otpServicePort = new ProviderConfigProperty();
        otpServicePort.setName("otp.port");
        otpServicePort.setLabel("Otp service port");
        otpServicePort.setType(ProviderConfigProperty.STRING_TYPE);
        otpServicePort.setHelpText("Otp service port");
        otpServicePort.setDefaultValue("80");

        configProperties.add(otpServiceHost);
        configProperties.add(otpServicePort);
    }


    @Override
    public String getHelpText() {
        return "Authentication against OTP service";
    }

    @Override
    public String getDisplayType() {
        return "Otp Authenticator";
    }

    @Override
    public String getReferenceCategory() {
        return "Otp Authenticator";
    }

    @Override
    public void init(Config.Scope config) {

    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {

    }

    @Override
    public void close() {

    }


}
