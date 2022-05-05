[![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=tmseidel_simple-oauth-server&metric=alert_status)](https://sonarcloud.io/summary/new_code?id=tmseidel_simple-oauth-server)

# Welcome to the simple-oauth-server project!

Secure your APIs and provide Single-Sign-On with **simple-oauth-server**. It's the easiest way to secure web-applications with the popular OAuth2 Protocol.

The goal of this project is to provide an OAuth2 Authentication & Authorization Backend for self-hosting. It's an alternative to the OAuth-Backends from big cloud-providers like AWS or Azure and the commercial ones like auth0.com.

In addition, it's way simpler than other OpenSource solutions like Keycloak achieved by keeping the features focussed on OAuth2.

## Use cases
* Add authentication and authorization to your application, either interactive with username/password or automatically via Machine-2-machine authentication. 
* Store your userdata globally and provide this data after an authentication to any application with OpenId-Connect.
* Provide Single-Sign-On (SSO) for all your applications.
* Store all your data on your own infrastructure and don't be dependent from any cloud-provider or other 3rd party.
* Use this project as Test-Mock for your application to simulate an OAuth2-Component. The REST-API of **simple-oauth-server** provides flawless setup and configuration from within your build-environment

## Features
* OAuth2-Login Flows for 
  * Traditional Web-applications
  * Mobile-Apps or Single-Page-Applications
  * Daemons or Headless applications
  * Devices
* REST-Services for Authorization and JWT Token-Usage
* Customizable Login Page

The following RFCs are implemented:
* [RFC6749 - OAuth 2.0](https://tools.ietf.org/html/rfc6749)
* [RFC7636 - Proof Key for Code Exchange by OAuth Public Clients](https://datatracker.ietf.org/doc/html/rfc7636)
* [RFC6750 - Bearer Token Usage](https://tools.ietf.org/html/rfc6750)
* [RFC6819 - OAuth 2.0 Threat Model and Security Considerations](https://tools.ietf.org/html/rfc6819)
* [RFC7009 - Token Revocation](https://datatracker.ietf.org/doc/html/rfc7009)
* [RFC7662 - Token Introspection](https://datatracker.ietf.org/doc/html/rfc7662)

## Documentation
Visit our [Documentation](https://github.com/tmseidel/simple-oauth-server/wiki)

## Support & Discussion
* Join our [Forums](https://github.com/tmseidel/simple-oauth-server/discussions)




 

