package com.boomi.flow.services.onelogin.onelogin;

import com.github.scribejava.core.builder.api.DefaultApi20;

public class OneLoginOpenIdApi20 extends DefaultApi20 {
    private final String region;

    public OneLoginOpenIdApi20(String region) {
        this.region = region;
    }

    @Override
    public String getAccessTokenEndpoint() {
        return String.format("https://%s.onelogin.com/oidc/token", this.region);
    }

    @Override
    protected String getAuthorizationBaseUrl() {
        return String.format("https://%s.onelogin.com/oidc/auth", this.region);
    }
}
