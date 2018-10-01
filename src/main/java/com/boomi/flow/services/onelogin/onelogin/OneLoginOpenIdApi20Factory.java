package com.boomi.flow.services.onelogin.onelogin;

import com.boomi.flow.services.onelogin.ApplicationConfiguration;
import com.github.scribejava.core.builder.ServiceBuilder;
import com.github.scribejava.core.oauth.OAuth20Service;

public class OneLoginOpenIdApi20Factory {
    public static OAuth20Service create(ApplicationConfiguration configuration, Boolean includeCallback) {

        ServiceBuilder builder = new ServiceBuilder(configuration.getOpenIdClientId())
                .apiSecret(configuration.getOpenIdClientSecret())
                .scope("openid profile groups");

        if (includeCallback) {
            builder.callback("https://flow.manywho.com/api/run/1/oauth2");
        }

        return builder.build(new OneLoginOpenIdApi20(configuration.getOpenIdClientRegion()));
    }
}
