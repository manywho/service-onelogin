package com.boomi.flow.services.onelogin.onelogin;

import com.boomi.flow.services.onelogin.ApplicationConfiguration;
import com.onelogin.sdk.conn.Client;

public class OneLoginApiFactory {
    public static Client create(ApplicationConfiguration configuration) {
        return new Client(configuration.getClientId(), configuration.getClientSecret(), configuration.getRegion());
    }
}
