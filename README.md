[![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=tmseidel_simple-oauth-server&metric=alert_status)](https://sonarcloud.io/summary/new_code?id=tmseidel_simple-oauth-server)

# Welcome to the simple-oauth-server project!

Secure your APIs and provide Single-Sign-On with **simple-oauth-server**. It's the easiest way to secure web-applications with the popular OAuth Protocol.

The goal of this project is to provide an OAuth Authentication & Authorization Backend for self-hosting. It's an alternative to the OAuth-Backends from big cloud-providers like AWS or Azure and the commercial ones like auth0.com.

In addition it's way simpler than other OpenSource solutions like Keycloak achieved by keeping the features focussed on OAuth.

## Use cases
* Add authentication and authorization to your application, either interactive with username/password or automatically via Machine-2-machine authentication. 
* Store your userdata globally and provide this data after an authentication to any application with OpenId-Connect.
* Provide Single-Sign-On (SSO) for all your applications.
* Store all your data on your own infrastructure and don't be dependent from any cloud-provider or other 3rd party.

The following RFCs are implemented:
* [RFC6749 - OAuth 2.0](https://tools.ietf.org/html/rfc6749)
* [RFC6750 - Bearer Token Usage](https://tools.ietf.org/html/rfc6750)
* [RFC6819 - OAuth 2.0 Threat Model and Security Considerations](https://tools.ietf.org/html/rfc6819)
* [RFC7009 - Token Revocation](https://datatracker.ietf.org/doc/html/rfc7009)
* [RFC7662 - Token Introspection](https://datatracker.ietf.org/doc/html/rfc7662)


## Features
* Support of the OAuth Authorization Flows
    * Authorization Code Flow
    * Hybrid Flow
    * Client Credentials Flow
    * Device Authorization Flow
* Customizable Login Page
* Full Configuration via REST-Interface

## Support & Discussion
* Join our [Google Group](https://groups.google.com/g/simple-oauth-server)

## Roadmap
### 0.1
* Client Credential Flow
### 0.2
* Authorization Flow
* Customizable Login-Pages
* OpenId Connect
### 0.3
* Device Authorization Flow
* Hybrid Flow
### 0.4
* Rest-Client for full control of the configuration


 

