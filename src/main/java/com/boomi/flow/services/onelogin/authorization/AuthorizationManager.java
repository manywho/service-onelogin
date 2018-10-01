package com.boomi.flow.services.onelogin.authorization;

import com.boomi.flow.services.onelogin.ApplicationConfiguration;
import com.boomi.flow.services.onelogin.onelogin.OneLoginApiFactory;
import com.boomi.flow.services.onelogin.onelogin.OneLoginOpenIdApi20Factory;
import com.github.scribejava.core.oauth.OAuth20Service;
import com.google.inject.Inject;
import com.manywho.sdk.api.AuthorizationType;
import com.manywho.sdk.api.run.elements.config.Group;
import com.manywho.sdk.api.run.elements.type.ObjectDataRequest;
import com.manywho.sdk.api.run.elements.type.ObjectDataResponse;
import com.manywho.sdk.api.security.AuthenticatedWho;
import com.manywho.sdk.services.configuration.ConfigurationParser;
import com.manywho.sdk.services.types.TypeBuilder;
import com.manywho.sdk.services.types.system.$User;
import com.manywho.sdk.services.types.system.AuthorizationAttribute;
import com.manywho.sdk.services.types.system.AuthorizationGroup;
import com.manywho.sdk.services.types.system.AuthorizationUser;
import com.manywho.sdk.services.utils.Streams;
import com.mashape.unirest.http.HttpResponse;
import com.mashape.unirest.http.JsonNode;
import com.mashape.unirest.http.Unirest;
import com.mashape.unirest.http.exceptions.UnirestException;
import com.onelogin.sdk.conn.Client;
import lombok.experimental.var;
import org.apache.oltu.oauth2.common.exception.OAuthProblemException;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.json.JSONObject;

import java.net.URISyntaxException;
import java.util.List;
import java.util.stream.Collectors;

public class AuthorizationManager {
    private final ConfigurationParser configurationParser;
    private final TypeBuilder typeBuilder;

    @Inject
    public AuthorizationManager(ConfigurationParser configurationParser, TypeBuilder typeBuilder) {
        this.configurationParser = configurationParser;
        this.typeBuilder = typeBuilder;
    }

    public ObjectDataResponse authorization(AuthenticatedWho authenticatedWho, ObjectDataRequest request) {
        ApplicationConfiguration configuration = configurationParser.from(request);

        String status;

        switch (request.getAuthorization().getGlobalAuthenticationType()) {
            case AllUsers:
                // If it's a public user (i.e. not logged in) then return a 401
                if (authenticatedWho.getUserId().equals("PUBLIC_USER")) {
                    status = "401";
                } else {
                    status = "200";
                }

                break;
            case Public:
                status = "200";
                break;
            case Specified:
                if (authenticatedWho.getUserId().equals("PUBLIC_USER")) {
                    status = "401";
                    break;
                }
                JSONObject user;

                try {

                    HttpResponse<JsonNode> response = Unirest.get(String.format("https://%s.onelogin.com/oidc/me", configuration.getOpenIdClientRegion()))
                            .header("Authorization", "Bearer " + authenticatedWho.getToken())
                            .asJson();

                    user = response.getBody().getObject();

                } catch (UnirestException e) {
                    throw new RuntimeException("Unable to fetch the user from Onelogin: " + e.getMessage(), e);
                }

                if (user == null) {
                    status = "401";
                    break;
                }

                // We need to check if the authenticated user is one of the authorized users by ID
                if (request.getAuthorization().hasUsers()) {
                    var isAuthorized = request.getAuthorization().getUsers().stream()
                            .anyMatch(u -> u.getAuthenticationId().equals(user.getString("sub")));

                    if (isAuthorized) {
                        status = "200";
                    } else {
                        status = "401";
                    }

                    break;
                }

                // We need to check if the authenticated user is a member of one of the given groups, by group ID
                if (request.getAuthorization().hasGroups()) {
                    // If the user is a member of no groups, then they're automatically not authorized
                    if (!user.has("groups")) {
                        status = "401";
                        break;
                    }

                    List<Group> authorizedGroups = request.getAuthorization().getGroups();

                    var isAuthorized = Streams.asStream(user.getJSONArray("groups"))
                            .anyMatch(group -> authorizedGroups.stream().anyMatch(g -> g.getAuthenticationId().equals(group)));

                    if (isAuthorized) {
                        status = "200";
                    } else {
                        status = "401";
                    }

                    break;
                }

                //If the user doesn't have any roles deny access
                status = "401";
                break;

            default:
                status = "401";
                break;
        }

        OAuth20Service service = OneLoginOpenIdApi20Factory.create(configuration, false);

        var user = new $User();
        user.setDirectoryId("Onelogin");
        user.setDirectoryName("Onelogin");
        user.setAuthenticationType(AuthorizationType.Oauth2);
        user.setLoginUrl(service.getAuthorizationUrl());
        user.setStatus(status);
        user.setUserId("");

        return new ObjectDataResponse(typeBuilder.from(user));
    }

    public ObjectDataResponse groupAttributes() {
        return new ObjectDataResponse(
                typeBuilder.from(new AuthorizationAttribute("member", "Member"))
        );
    }

    public ObjectDataResponse roles(ObjectDataRequest request) {
        ApplicationConfiguration configuration = configurationParser.from(request);

        Client client = OneLoginApiFactory.create(configuration);

        try {
            // Build the required AuthorizationGroup objects out of the groups that Okta tells us about
            var roles = Streams.asStream(client.getRoles().iterator())
                    .map(role -> new AuthorizationGroup(role.getName(), role.getName()))
                    .collect(Collectors.toList());

            return new ObjectDataResponse(typeBuilder.from(roles));

        } catch (URISyntaxException | OAuthProblemException | OAuthSystemException e) {
            throw new RuntimeException("Cannot get roles from OneLogin", e);
        }
    }

    public ObjectDataResponse userAttributes() {
        return new ObjectDataResponse(
                typeBuilder.from(new AuthorizationAttribute("user", "User"))
        );
    }

    public ObjectDataResponse users(ObjectDataRequest request) {
        ApplicationConfiguration configuration = configurationParser.from(request);

        Client client = OneLoginApiFactory.create(configuration);

        try {
            // Build the required AuthorizationUser objects out of the users that Okta tells us about
            var users = Streams.asStream(client.getUsers().iterator())
                    .map(user -> new AuthorizationUser(
                            String.valueOf(user.id),
                            String.format("%s %s", user.firstname, user.lastname),
                            user.email
                    ))
                    .collect(Collectors.toList());

            return new ObjectDataResponse(
                    typeBuilder.from(users)
            );
        } catch (URISyntaxException | OAuthProblemException | OAuthSystemException e) {
            throw new RuntimeException("Cannot get groups from OneLogin", e);
        }
    }
}
