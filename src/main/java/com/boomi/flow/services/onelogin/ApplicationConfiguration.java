package com.boomi.flow.services.onelogin;

import com.manywho.sdk.api.ContentType;
import com.manywho.sdk.services.configuration.Configuration;

public class ApplicationConfiguration implements Configuration {
    @Configuration.Setting(name = "OpenId Client ID", contentType = ContentType.String)
    private String openIdClientId;

    @Configuration.Setting(name = "OpenId Client Secret", contentType = ContentType.Password)
    private String openIdClientSecret;

    @Configuration.Setting(name = "OpenId Client Region", contentType = ContentType.String)
    private String openIdClientRegion;

    @Configuration.Setting(name = "Region (Api Access)", contentType = ContentType.String)
    private String region;

    @Configuration.Setting(name = "Client ID (Api Access)", contentType = ContentType.String)
    private String clientId;

    @Configuration.Setting(name = "Client Secret (Api Access)", contentType = ContentType.Password)
    private String clientSecret;

    public String getOpenIdClientId() {
        return openIdClientId;
    }

    public String getOpenIdClientSecret() {
        return openIdClientSecret;
    }

    public String getOpenIdClientRegion() {
        return openIdClientRegion;
    }

    public String getRegion() {
        return region;
    }

    public String getClientId() {
        return clientId;
    }

    public String getClientSecret() {
        return clientSecret;
    }
}
