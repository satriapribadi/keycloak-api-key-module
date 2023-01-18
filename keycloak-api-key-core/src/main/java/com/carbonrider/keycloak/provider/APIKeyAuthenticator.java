package com.carbonrider.keycloak.provider;

/*
 * Copyright 2022 Carbonrider.com and/or its affiliates
 * and other contributors as mentioned in author tags.
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

import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.authenticators.browser.AbstractUsernameFormAuthenticator;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

import java.util.List;
import java.util.stream.Collectors;

/*
 * @author Yogesh Jadhav
 */

public class APIKeyAuthenticator extends AbstractUsernameFormAuthenticator implements Authenticator {

    public static final String API_KEY_HEADER_ATTRIBUTE = "x-api-key";
    public static final String CLIENT_ID_HEADER_ATTRIBUTE = "x-client-id";

    private final KeycloakSession session;

    public APIKeyAuthenticator(KeycloakSession session) {
        this.session = session;
    }

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        List<String> apiKeyCollection = context.getHttpRequest().getHttpHeaders().getRequestHeader(API_KEY_HEADER_ATTRIBUTE);
        if (apiKeyCollection == null || apiKeyCollection.isEmpty()) {
            return;
        }

        List<String> clientIdCollection = context.getHttpRequest().getHttpHeaders().getRequestHeader(CLIENT_ID_HEADER_ATTRIBUTE);
        if (clientIdCollection == null || clientIdCollection.isEmpty()) {
            return;
        }

        String apiKey = apiKeyCollection.get(0);
        String clientId = clientIdCollection.get(0);

        RealmModel realm = this.session.getContext().getRealm();

        List<UserModel> result =
                session
                        .users()
                        .searchForUserByUserAttributeStream(session.realms().getRealm(realm.getName()), clientId, apiKey)
                        .collect(Collectors.toList());

        if(result.isEmpty()) {
            return;
        }

        UserModel user = result.get(0);

        if (!enabledUser(context, user)) {
            context.cancelLogin();
            return;
        }

        context.setUser(user);
        context.success();
    }

    @Override
    public void action(AuthenticationFlowContext authenticationFlowContext) {
    }

    @Override
    public boolean requiresUser() {
        return false;
    }

    @Override
    public boolean configuredFor(KeycloakSession keycloakSession, RealmModel realmModel, UserModel userModel) {
        return true;
    }

    @Override
    public void setRequiredActions(KeycloakSession keycloakSession, RealmModel realmModel, UserModel userModel) {
    }

    @Override
    public void close() {
    }
}
