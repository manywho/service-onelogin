package com.boomi.flow.services.onelogin.authentication;

import com.boomi.flow.services.onelogin.ApplicationConfiguration;
import com.boomi.flow.services.onelogin.onelogin.OneLoginOpenIdApi20Factory;
import com.github.scribejava.core.model.OAuth2AccessToken;
import com.manywho.sdk.api.security.AuthenticatedWhoResult;
import com.manywho.sdk.api.security.AuthenticationCredentials;
import com.manywho.sdk.services.configuration.ConfigurationParser;
import com.mashape.unirest.http.HttpResponse;
import com.mashape.unirest.http.JsonNode;
import com.mashape.unirest.http.Unirest;
import com.mashape.unirest.http.exceptions.UnirestException;
import org.json.JSONObject;

import javax.inject.Inject;
import java.io.IOException;
import java.util.concurrent.ExecutionException;

public class AuthenticationManager {
    private final ConfigurationParser configurationParser;

    @Inject
    public AuthenticationManager(ConfigurationParser configurationParser) {
        this.configurationParser = configurationParser;
    }

    public AuthenticatedWhoResult authentication(AuthenticationCredentials credentials) {
        ApplicationConfiguration configuration = configurationParser.from(credentials);

        OAuth2AccessToken token;

        try {
            token = OneLoginOpenIdApi20Factory.create(configuration, true)
                    .getAccessToken(credentials.getCode());
        } catch (IOException | InterruptedException | ExecutionException e) {
            throw new RuntimeException("Unable to get the access token from OneLogin: " + e.getMessage(), e);
        }

        if (token == null) {
            throw new RuntimeException("An empty access token was given back from Onelogin");
        }

        JSONObject user;

        try {
            HttpResponse<JsonNode> response = Unirest.get(String.format("https://%s.onelogin.com/oidc/me", configuration.getOpenIdClientRegion()))
                    .header("Authorization", "Bearer " + token.getAccessToken())
                    .asJson();

            user = response.getBody().getObject();
        } catch (UnirestException e) {
            throw new RuntimeException("Unable to fetch the user from Onelogin: " + e.getMessage(), e);
        }

        // Build up the profile result from the information Okta gives us
        AuthenticatedWhoResult result = new AuthenticatedWhoResult();
        result.setDirectoryId("onelogin");
        result.setDirectoryName("Onelogin");
        result.setEmail(user.getString("email"));
        result.setFirstName(user.getString("given_name"));
        result.setIdentityProvider("?");
        result.setLastName(user.getString("family_name"));
        result.setStatus(AuthenticatedWhoResult.AuthenticationStatus.Authenticated);
        result.setTenantName("?");
        result.setToken(token.getAccessToken());
        result.setUserId(user.getString("sub"));
        result.setUsername(user.getString("email"));

        return result;
    }
}
