package com.vmokrecov.authservice.config;

public class AuthorizedGrantTypes {

    public static final String PASSWORD_TYPE = "password";
    public static final String IMPLICIT = "implicit";
    public static final String REFRESH_TOKEN = "refresh_token";
    public static final String CLIENT_CREDENTIALS = "client_credentials";
    public static final String AUTHORIZATIION_CODE = "authorization_code";

    private AuthorizedGrantTypes() {}
}
