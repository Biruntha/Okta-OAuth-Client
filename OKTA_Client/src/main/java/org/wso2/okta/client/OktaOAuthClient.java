/*
 * Copyright (c) 2018, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * you may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.wso2.okta.client;

import org.apache.commons.io.IOUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.HttpStatus;
import org.apache.http.NameValuePair;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpDelete;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpPut;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.message.BasicNameValuePair;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;
import org.wso2.carbon.apimgt.api.APIManagementException;
import org.wso2.carbon.apimgt.api.model.*;
import org.wso2.carbon.apimgt.impl.APIConstants;
import org.wso2.carbon.apimgt.impl.AbstractKeyManager;
import org.wso2.carbon.apimgt.impl.factory.KeyManagerHolder;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.util.*;

/**
 * This class provides the implementation to use "Okta" for managing
 * OAuth clients and Tokens needed by WSO2 API Manager.
 */
public class OktaOAuthClient extends AbstractKeyManager {
    private static final Log log = LogFactory.getLog(OktaOAuthClient.class);

    private KeyManagerConfiguration configuration;

    /**
     * {@code APIManagerComponent} calls this method, passing KeyManagerConfiguration as a {@code String}.
     *
     * @param keyManagerConfiguration Configuration as a {@link org.wso2.carbon.apimgt.api.model.KeyManagerConfiguration}
     * @throws APIManagementException This is the custom exception class for API management.
     */
    @Override
    public void loadConfiguration(KeyManagerConfiguration keyManagerConfiguration) throws APIManagementException {
        this.configuration = keyManagerConfiguration;
    }

    /**
     * This method will Register an OAuth client in Okta Authorization Server.
     *
     * @param oAuthAppRequest This object holds all parameters required to register an OAuth client.
     * @throws APIManagementException This is the custom exception class for API management.
     */
    @Override
    public OAuthApplicationInfo createApplication(OAuthAppRequest oAuthAppRequest) throws APIManagementException {
        if (log.isDebugEnabled()) {
            log.debug("Creating an OAuth Client in OKTA Authorization Server");
        }

        OAuthApplicationInfo oAuthApplicationInfo = oAuthAppRequest.getOAuthApplicationInfo();

        // Getting Client Instance Url and API Key from Config.
        String oktaInstanceUrl = configuration.getParameter(OktaConstants.OKTA_INSTANCE_URL);
        String apiKey = configuration.getParameter(OktaConstants.REGISTRAION_API_KEY);
        String registrationEndpoint = oktaInstanceUrl + "/oauth2/v1/clients";
        String[] scope = ((String) oAuthApplicationInfo.getParameter(OktaConstants.TOKEN_SCOPE)).split(",");
        Object tokenGrantType = oAuthApplicationInfo.getParameter(OktaConstants.TOKEN_GRANT_TYPE);

        CloseableHttpClient httpClient = HttpClientBuilder.create().build();
        BufferedReader reader = null;
        Map<String, Object> paramMap = new HashMap<String, Object>();
        try {
            // Create the JSON Payload that should be sent to OAuth Server.
            String jsonPayload = createJsonPayloadFromOauthApplication(oAuthApplicationInfo, paramMap);
            if (log.isDebugEnabled()) {
                log.debug("Payload to create new client : " + jsonPayload);
            }

            HttpPost httpPost = new HttpPost(registrationEndpoint);
            httpPost.setEntity(new StringEntity(jsonPayload, OktaConstants.UTF_8));
            httpPost.setHeader(OktaConstants.HTTP_HEADER_CONTENT_TYPE, OktaConstants.APPLICATION_JSON);
            // Setting Authorization Header, with API Key.
            httpPost.setHeader(OktaConstants.AUTHORIZATION, OktaConstants.AUTHENTICATION_SSWS + apiKey);

            if (log.isDebugEnabled()) {
                log.debug("invoking HTTP request to create new client");
            }
            HttpResponse response = httpClient.execute(httpPost);
            int statusCode = response.getStatusLine().getStatusCode();
            HttpEntity entity = response.getEntity();
            reader = new BufferedReader(new InputStreamReader(entity.getContent(), OktaConstants.UTF_8));
            JSONObject responseObject = getParsedObjectByReader(reader);

            // If successful a 201 will be returned.
            if (HttpStatus.SC_CREATED == statusCode) {
                if (responseObject != null) {
                    oAuthApplicationInfo = createOAuthAppInfoFromResponse(responseObject);
                    oAuthApplicationInfo.addParameter(OktaConstants.TOKEN_SCOPE, scope);
                    oAuthApplicationInfo.addParameter(OktaConstants.TOKEN_GRANT_TYPE, tokenGrantType);

                    return oAuthApplicationInfo;
                }
            } else {
                handleException("Some thing wrong here while registering the new client. " +
                        "Response : " + responseObject.toJSONString());
            }
        } catch (UnsupportedEncodingException e) {
            handleException("Encoding for the Response not-supported.", e);
        } catch (ParseException e) {
            handleException("Error while parsing response json", e);
        } catch (IOException e) {
            handleException("Error while reading response body ", e);
        } finally {
            closeResources(reader, httpClient);
        }
        return null;
    }

    /**
     * This method will update an existing OAuth client in Okta Authorization Server.
     *
     * @param oAuthAppRequest Parameters to be passed to Authorization Server,
     *                        encapsulated as an {@code OAuthAppRequest}
     * @return Details of updated OAuth Client.
     * @throws APIManagementException This is the custom exception class for API management.
     */
    @Override
    public OAuthApplicationInfo updateApplication(OAuthAppRequest oAuthAppRequest) throws APIManagementException {
        Object updateAppInOkta = oAuthAppRequest.getOAuthApplicationInfo().getParameter(OktaConstants.UPDATE_APP_IN_OKTA);
        if (updateAppInOkta != null && Boolean.valueOf(updateAppInOkta.toString())) {
            if (log.isDebugEnabled()) {
                log.debug("Updating an OAuth Client in OKTA Authorization Server");
            }

            OAuthApplicationInfo oAuthApplicationInfo = oAuthAppRequest.getOAuthApplicationInfo();

            // We have to send the client id with the update request.
            String clientId = oAuthApplicationInfo.getClientId();
            // Getting Client Instance Url and API Key from Config.
            String oktaInstanceUrl = configuration.getParameter(OktaConstants.OKTA_INSTANCE_URL);
            String apiKey = configuration.getParameter(OktaConstants.REGISTRAION_API_KEY);
            String registrationEndpoint = oktaInstanceUrl + "/oauth2/v1/clients";
            registrationEndpoint += "/" + clientId;

            CloseableHttpClient httpClient = HttpClientBuilder.create().build();
            BufferedReader reader = null;
            Map<String, Object> paramMap = new HashMap<String, Object>();
            if (StringUtils.isNotEmpty(clientId)) {
                paramMap.put(OktaConstants.CLIENT_ID, clientId);
            }

            try {
                // Create the JSON Payload that should be sent to OAuth Server.
                String jsonPayload = createJsonPayloadFromOauthApplication(oAuthApplicationInfo, paramMap);
                if (log.isDebugEnabled()) {
                    log.debug("Payload to update an OAuth client : " + jsonPayload);
                }

                HttpPut httpPut = new HttpPut(registrationEndpoint);
                httpPut.setEntity(new StringEntity(jsonPayload, OktaConstants.UTF_8));
                httpPut.setHeader(OktaConstants.HTTP_HEADER_CONTENT_TYPE, OktaConstants.APPLICATION_JSON);
                // Setting Authorization Header, with API Key.
                httpPut.setHeader(OktaConstants.AUTHORIZATION, OktaConstants.AUTHENTICATION_SSWS + apiKey);
                if (log.isDebugEnabled()) {
                    log.debug("invoking HTTP request to update client");
                }
                HttpResponse response = httpClient.execute(httpPut);
                int statusCode = response.getStatusLine().getStatusCode();

                HttpEntity entity = response.getEntity();
                reader = new BufferedReader(new InputStreamReader(entity.getContent(), OktaConstants.UTF_8));
                JSONObject responseObject = getParsedObjectByReader(reader);
                if (statusCode == HttpStatus.SC_OK) {
                    if (responseObject != null) {
                        log.info("Successfully updated OAuth client.");
                        return createOAuthAppInfoFromResponse(responseObject);
                    } else {
                        handleException("ResponseObject is empty. Can not return oAuthApplicationInfo.");
                    }
                } else {
                    handleException("Some thing wrong here when updating the Client with Consumer Key " + clientId +
                            ": Response: " + responseObject.toJSONString());
                }
            } catch (UnsupportedEncodingException e) {
                handleException("Some thing wrong here when Updating a Client for Consumer Key " + clientId, e);
            } catch (ParseException e) {
                handleException("Error while parsing response json", e);
            } catch (IOException e) {
                handleException("Error while reading response body from Server ", e);
            } finally {
                closeResources(reader, httpClient);
            }
        }
        return null;
    }

    /**
     * Deletes OAuth Client from Authorization Server.
     *
     * @param clientId consumer key of the OAuth Client.
     * @throws APIManagementException This is the custom exception class for API management.
     */
    @Override
    public void deleteApplication(String clientId) throws APIManagementException {
        if (log.isDebugEnabled()) {
            log.debug("Deleting an OAuth Client in OKTA Authorization Server for clientId:" + clientId);
        }

        // Getting Client Instance Url and API Key from Config.
        String oktaInstanceUrl = configuration.getParameter(OktaConstants.OKTA_INSTANCE_URL);
        String apiKey = configuration.getParameter(OktaConstants.REGISTRAION_API_KEY);
        String registrationEndpoint = oktaInstanceUrl + "/oauth2/v1/clients";
        registrationEndpoint += "/" + clientId;

        BufferedReader reader = null;
        CloseableHttpClient httpClient = HttpClientBuilder.create().build();
        try {
            HttpDelete httpDelete = new HttpDelete(registrationEndpoint);
            // Set Authorization Header, with API Key.
            httpDelete.addHeader(OktaConstants.AUTHORIZATION, OktaConstants.AUTHENTICATION_SSWS + apiKey);
            if (log.isDebugEnabled()) {
                log.debug("invoking HTTP request to delete the client ");
            }
            HttpResponse response = httpClient.execute(httpDelete);
            int statusCode = response.getStatusLine().getStatusCode();
            if (statusCode == HttpStatus.SC_NO_CONTENT) {
                log.info("OAuth Client for consumer Id " + clientId + " has been successfully deleted");
            } else {
                HttpEntity entity = response.getEntity();
                reader = new BufferedReader(new InputStreamReader(entity.getContent(), OktaConstants.UTF_8));
                JSONObject responseObject = getParsedObjectByReader(reader);
                handleException("Problem occurred while deleting client for Consumer Key " + clientId + "Response : "
                        + responseObject.toJSONString());
            }
        } catch (IOException e) {
            handleException("Error while reading response body from Server ", e);
        } catch (ParseException e) {
            handleException("Error while parsing response json", e);
        } finally {
            closeResources(reader, httpClient);
        }
    }

    /**
     * This method retrieves OAuth application details by given consumer key.
     *
     * @param clientId consumer key of the OAuth Client.
     * @return an {@code OAuthApplicationInfo} having all the details of an OAuth Client.
     * @throws APIManagementException This is the custom exception class for API management.
     */
    @Override
    public OAuthApplicationInfo retrieveApplication(String clientId) throws APIManagementException {
        if (log.isDebugEnabled()) {
            log.debug("Retrieving an OAuth Client from OKTA Authorization Server");
        }
        // Getting Client Instance Url and API Key from Config.
        String oktaInstanceUrl = configuration.getParameter(OktaConstants.OKTA_INSTANCE_URL);
        String apiKey = configuration.getParameter(OktaConstants.REGISTRAION_API_KEY);
        String registrationEndpoint = oktaInstanceUrl + "/oauth2/v1/clients";
        if (StringUtils.isNotEmpty(clientId)) {
            registrationEndpoint += "/" + clientId;
        }

        CloseableHttpClient httpClient = HttpClientBuilder.create().build();
        BufferedReader reader = null;
        try {
            HttpGet request = new HttpGet(registrationEndpoint);
            // Set authorization header, with API key.
            request.addHeader(OktaConstants.AUTHORIZATION, OktaConstants.AUTHENTICATION_SSWS + apiKey);
            if (log.isDebugEnabled()) {
                log.debug("invoking HTTP request to get the client details");
            }
            HttpResponse response = httpClient.execute(request);
            int statusCode = response.getStatusLine().getStatusCode();
            HttpEntity entity = response.getEntity();
            reader = new BufferedReader(new InputStreamReader(entity.getContent(), OktaConstants.UTF_8));
            Object responseJSON;

            if (statusCode == HttpStatus.SC_OK) {
                JSONParser parser = new JSONParser();
                responseJSON = parser.parse(reader);
                return createOAuthAppInfoFromResponse((JSONObject) responseJSON);
            } else {
                handleException("Something went wrong while retrieving client for consumer key " + clientId);
            }
        } catch (ParseException e) {
            handleException("Error while parsing response json.", e);
        } catch (IOException e) {
            handleException("Error while reading response body.", e);
        } finally {
            closeResources(reader, httpClient);
        }
        return null;
    }

    /**
     * Gets new access token and returns it in an AccessTokenInfo object.
     *
     * @param accessTokenRequest Info of the token needed.
     * @return AccessTokenInfo Info of the new token.
     * @throws APIManagementException This is the custom exception class for API management.
     */
    @Override
    public AccessTokenInfo getNewApplicationAccessToken(AccessTokenRequest accessTokenRequest)
            throws APIManagementException {
        if (log.isDebugEnabled()) {
            log.debug("Get new client access token from Authorization Server");
        }

        AccessTokenInfo tokenInfo = new AccessTokenInfo();
        String accessToken = accessTokenRequest.getTokenToRevoke();
        if (StringUtils.isNotEmpty(accessToken)) {
            revokeAccessToken(accessTokenRequest.getClientId(), accessTokenRequest.getClientSecret(), accessToken);
        }
        List<NameValuePair> parameters = new ArrayList<NameValuePair>();
        Object grantType = accessTokenRequest.getGrantType();
        if (grantType == null) {
            grantType = OktaConstants.GRANT_TYPE_CLIENT_CREDENTIALS;
        }
        parameters.add(new BasicNameValuePair(OktaConstants.GRANT_TYPE, (String) grantType));
        String scopeString = convertToString(accessTokenRequest.getScope());
        if (StringUtils.isEmpty(scopeString)) {
            handleException("Scope cannot be empty");
        } else {
            parameters.add(new BasicNameValuePair(OktaConstants.ACCESS_TOKEN_SCOPE, scopeString));
        }

        JSONObject responseJSON = getAccessToken(accessTokenRequest.getClientId(), accessTokenRequest.getClientSecret(),
                parameters);

        if (responseJSON != null) {
            updateTokenInfo(tokenInfo, responseJSON);
            log.info("OAuth token successfully validated.");

            return tokenInfo;
        } else {
            tokenInfo.setTokenValid(false);
            tokenInfo.setErrorcode(APIConstants.KeyValidationStatus.API_AUTH_INVALID_CREDENTIALS);
            log.info("OAuth token failed to validate.");
        }

        return tokenInfo;
    }

    /**
     * This is used to build accesstoken request from OAuth application info.
     *
     * @param oAuthApplication OAuth application details.
     * @param tokenRequest     AccessTokenRequest that is need to be updated with addtional info.
     * @return AccessTokenRequest after adding OAuth application details.
     * @throws APIManagementException This is the custom exception class for API management.
     */
    public AccessTokenRequest buildAccessTokenRequestFromOAuthApp(
            OAuthApplicationInfo oAuthApplication, AccessTokenRequest tokenRequest) throws APIManagementException {

        if (oAuthApplication == null) {
            return tokenRequest;
        }
        if (tokenRequest == null) {
            tokenRequest = new AccessTokenRequest();
        }

        if (oAuthApplication.getClientId() == null || oAuthApplication.getClientSecret() == null) {
            throw new APIManagementException("Consumer key or Consumer Secret missing.");
        }
        tokenRequest.setClientId(oAuthApplication.getClientId());
        tokenRequest.setClientSecret(oAuthApplication.getClientSecret());

        if (oAuthApplication.getParameter(OktaConstants.TOKEN_SCOPE) != null) {
            String[] tokenScopes = null;

            if (oAuthApplication.getParameter(OktaConstants.TOKEN_SCOPE) instanceof String[]) {
                tokenScopes = (String[]) oAuthApplication.getParameter(OktaConstants.TOKEN_SCOPE);
            }
            if (oAuthApplication.getParameter(OktaConstants.TOKEN_SCOPE) instanceof String) {
                tokenScopes = oAuthApplication.getParameter(OktaConstants.TOKEN_SCOPE).toString().split(",");
            }
            tokenRequest.setScope(tokenScopes);
            oAuthApplication.addParameter(OktaConstants.TOKEN_SCOPE, Arrays.toString(tokenScopes));
        }

        if (oAuthApplication.getParameter(ApplicationConstants.VALIDITY_PERIOD) != null) {
            tokenRequest.setValidityPeriod(Long.parseLong((String) oAuthApplication.getParameter(ApplicationConstants
                    .VALIDITY_PERIOD)));
        }

        Object grantType = oAuthApplication.getParameter(OktaConstants.TOKEN_GRANT_TYPE);
        if (grantType != null) {
            tokenRequest.setGrantType((String) grantType);
        }

        return tokenRequest;
    }

    /**
     * This method will accept json String and will do the json parse will set oAuth application properties to
     * OAuthApplicationInfo object.
     *
     * @param oAuthApplicationInfo OAuthApplicationInfo.
     * @param jsonInput            this jsonInput will contain set of oAuth application properties.
     * @return OAuthApplicationInfo object will be return.
     * @throws APIManagementException This is the custom exception class for API management.
     */
    public OAuthApplicationInfo buildFromJSON(OAuthApplicationInfo oAuthApplicationInfo, String jsonInput) throws
            APIManagementException {

        JSONParser parser = new JSONParser();
        JSONObject jsonObject;

        try {
            jsonObject = (JSONObject) parser.parse(jsonInput);
            if (jsonObject != null) {
                Map<String, Object> params = new HashMap<String, Object>();

                for (Object object : jsonObject.keySet()) {
                    String key = (String) object;
                    Object keyValue = jsonObject.get(key);
                    params.put(key, keyValue);
                }

                if (params.get(OktaConstants.CLIENT_SECRET) != null) {
                    oAuthApplicationInfo.setClientSecret((String) params.get(OktaConstants.CLIENT_SECRET));
                }

                oAuthApplicationInfo.putAll(params);
                return oAuthApplicationInfo;
            }
        } catch (ParseException e) {
            handleException("Error occurred while parsing JSON String", e);
        }
        return null;
    }

    /**
     * This is used to get the meta data of the accesstoken.
     *
     * @param accessToken AccessToken.
     * @return The meta data details of accesstoken.
     * @throws APIManagementException This is the custom exception class for API management.
     */
    @Override
    public AccessTokenInfo getTokenMetaData(String accessToken) throws APIManagementException {
        if (log.isDebugEnabled()) {
            log.debug("Getting token metadata from Authorization Server");
        }
        AccessTokenInfo tokenInfo = new AccessTokenInfo();

        KeyManagerConfiguration config = KeyManagerHolder.getKeyManagerInstance().getKeyManagerConfiguration();
        // Getting Client Instance Url, authorization server Id, clientId and clientSecret from Config.
        String oktaInstanceUrl = configuration.getParameter(OktaConstants.OKTA_INSTANCE_URL);
        String authorizationServerId = configuration.getParameter(OktaConstants.OKTA_AUTHORIZATION_SERVER_ID);
        String introspectionURL = oktaInstanceUrl + "/oauth2/" + authorizationServerId + "/v1/introspect";
        String clientId = config.getParameter(OktaConstants.CLIENT_ID);
        String clientSecret = config.getParameter(OktaConstants.CLIENT_SECRET);
        String encodedCredentials;
        try {
            encodedCredentials = Base64.getEncoder().encodeToString((clientId + ":" + clientSecret)
                    .getBytes(OktaConstants.UTF_8));
        } catch (UnsupportedEncodingException e) {
            throw new APIManagementException("Unsupported encoding: ", e);
        }

        CloseableHttpClient httpClient = HttpClientBuilder.create().build();
        BufferedReader reader = null;

        try {
            List<NameValuePair> parameters = new ArrayList<NameValuePair>();
            parameters.add(new BasicNameValuePair(OktaConstants.TOKEN, accessToken));
            parameters.add(new BasicNameValuePair(OktaConstants.TOKEN_TYPE_HINT, OktaConstants.ACCESS_TOKEN));

            HttpPost httpPost = new HttpPost(introspectionURL);
            httpPost.setEntity(new UrlEncodedFormEntity(parameters));
            httpPost.setHeader(OktaConstants.AUTHORIZATION, OktaConstants.AUTHENTICATION_BASIC + encodedCredentials);
            if (log.isDebugEnabled()) {
                log.debug("Invoking HTTP request to get token info.");
            }
            HttpResponse response = httpClient.execute(httpPost);
            int statusCode = response.getStatusLine().getStatusCode();
            JSONObject responseJSON;

            if (HttpStatus.SC_OK == statusCode) {
                HttpEntity entity = response.getEntity();
                reader = new BufferedReader(new InputStreamReader(entity.getContent(), OktaConstants.UTF_8));
                responseJSON = getParsedObjectByReader(reader);

                if (responseJSON != null) {
                    tokenInfo.setTokenValid((Boolean) responseJSON.get(OktaConstants.ACCESS_TOKEN_ACTIVE));

                    if (tokenInfo.isTokenValid()) {
                        long expiryTime = (Long) responseJSON.get(OktaConstants.ACCESS_TOKEN_EXPIRY);
                        long issuedTime = (Long) responseJSON.get(OktaConstants.ACCESS_TOKEN_ISSUED);
                        tokenInfo.setValidityPeriod(expiryTime - issuedTime);

                        String tokScopes = (String) responseJSON.get(OktaConstants.ACCESS_TOKEN_SCOPE);

                        if (StringUtils.isNotEmpty(tokScopes)) {
                            tokenInfo.setScope(tokScopes.split("\\s+"));
                        }

                        tokenInfo.setIssuedTime(issuedTime);
                        tokenInfo.setConsumerKey((String) responseJSON.get(OktaConstants.CLIENT_ID));
                        tokenInfo.setEndUserName((String) responseJSON.get(OktaConstants.ACCESS_TOKEN_USER_NAME));
                        tokenInfo.addParameter(OktaConstants.ACCESS_TOKEN_SUBJECT,
                                responseJSON.get(OktaConstants.ACCESS_TOKEN_SUBJECT));
                        tokenInfo.addParameter(OktaConstants.ACCESS_TOKEN_AUDIENCE,
                                responseJSON.get(OktaConstants.ACCESS_TOKEN_AUDIENCE));
                        tokenInfo.addParameter(OktaConstants.ACCESS_TOKEN_ISSUER,
                                responseJSON.get(OktaConstants.ACCESS_TOKEN_ISSUER));
                        tokenInfo.addParameter(OktaConstants.ACCESS_TOKEN_TYPE,
                                responseJSON.get(OktaConstants.ACCESS_TOKEN_TYPE));
                        tokenInfo.addParameter(OktaConstants.ACCESS_TOKEN_USER_ID,
                                responseJSON.get(OktaConstants.ACCESS_TOKEN_USER_ID));
                        tokenInfo.addParameter(OktaConstants.ACCESS_TOKEN_IDENTIFIER,
                                responseJSON.get(OktaConstants.ACCESS_TOKEN_IDENTIFIER));

                        return tokenInfo;
                    }
                } else {
                    log.error("Invalid Token " + accessToken);
                    tokenInfo.setTokenValid(false);
                    tokenInfo.setErrorcode(APIConstants.KeyValidationStatus.API_AUTH_INVALID_CREDENTIALS);
                    return tokenInfo;
                }
            } else {
                log.error("Invalid Token " + accessToken);
                tokenInfo.setTokenValid(false);
                tokenInfo.setErrorcode(APIConstants.KeyValidationStatus.API_AUTH_INVALID_CREDENTIALS);
                return tokenInfo;
            }
        } catch (ParseException e) {
            handleException("Error while parsing response json " + e.getMessage(), e);
        } catch (UnsupportedEncodingException e) {
            handleException("The Character Encoding is not supported. " + e.getMessage(), e);
        } catch (ClientProtocolException e) {
            handleException("HTTP request error has occurred while sending request to OAuth Provider. " +
                    e.getMessage(), e);
        } catch (IOException e) {
            handleException("Error has occurred while reading or closing buffer reader. " + e.getMessage(), e);
        } finally {
            closeResources(reader, httpClient);
        }

        return null;
    }

    @Override
    public KeyManagerConfiguration getKeyManagerConfiguration() throws APIManagementException {
        return configuration;
    }

    @Override
    public OAuthApplicationInfo buildFromJSON(String s) throws APIManagementException {
        return null;
    }

    /**
     * This method will be called when mapping existing OAuth Clients with Application in API Manager
     *
     * @param oAuthAppRequest Details of the OAuth Client to be mapped.
     * @return {@code OAuthApplicationInfo} with the details of the mapped client.
     * @throws APIManagementException This is the custom exception class for API management.
     */
    @Override
    public OAuthApplicationInfo mapOAuthApplication(OAuthAppRequest oAuthAppRequest) throws APIManagementException {
        return oAuthAppRequest.getOAuthApplicationInfo();
    }

    @Override
    public boolean registerNewResource(API api, Map resourceAttributes) throws APIManagementException {
        return true;
    }

    @Override
    public Map getResourceByApiId(String apiId) throws APIManagementException {
        return null;
    }

    @Override
    public boolean updateRegisteredResource(API api, Map resourceAttributes) throws APIManagementException {
        return true;
    }

    @Override
    public void deleteRegisteredResourceByAPIId(String apiID) throws APIManagementException {

    }

    @Override
    public void deleteMappedApplication(String s) throws APIManagementException {

    }

    @Override
    public Set<String> getActiveTokensByConsumerKey(String s) throws APIManagementException {
        return null;
    }

    @Override
    public AccessTokenInfo getAccessTokenByConsumerKey(String s) throws APIManagementException {
        return null;
    }

    /**
     * This method can be used to create a JSON Payload out of the Parameters defined in an OAuth Application
     * in order to create and update the client.
     *
     * @param oAuthApplicationInfo Object that needs to be converted.
     * @param paramMap             It has additional parameters to create the Json payload.
     * @return JSON payload.
     * @throws APIManagementException This is the custom exception class for API management.
     */
    private String createJsonPayloadFromOauthApplication(OAuthApplicationInfo oAuthApplicationInfo,
                                                         Map<String, Object> paramMap) throws APIManagementException {
        if (log.isDebugEnabled()) {
            log.debug("Creating JsonPayload from Oauth Application info.");
        }
        String clientName = oAuthApplicationInfo.getClientName();
        if (StringUtils.isNotEmpty(clientName)) {
            paramMap.put(OktaConstants.CLIENT_NAME, clientName);
        }

        String clientRedirectUri = oAuthApplicationInfo.getCallBackURL();
        if (StringUtils.isNotEmpty(clientRedirectUri)) {
            List<String> redirectUris = Collections.singletonList(clientRedirectUri);
            paramMap.put(OktaConstants.CLIENT_REDIRECT_URIS, redirectUris);
        } else {
            handleException("Mandatory parameter CallBackURL is missing");
        }

        Object clientResponseTypes = oAuthApplicationInfo.getParameter(OktaConstants.CLIENT_RESPONSE_TYPES);
        if (clientResponseTypes != null) {
            String[] responseTypes = ((String) clientResponseTypes).split(",");
            JSONArray jsonArray = new JSONArray();
            Collections.addAll(jsonArray, responseTypes);
            paramMap.put(OktaConstants.CLIENT_RESPONSE_TYPES, jsonArray);
        } else {
            handleException("Mandatory parameter response_types is missing");
        }

        Object clientGrantTypes = oAuthApplicationInfo.getParameter(OktaConstants.CLIENT_GRANT_TYPES);
        if (clientGrantTypes != null) {
            String[] grantTypes = ((String) clientGrantTypes).split(",");
            JSONArray jsonArray = new JSONArray();
            Collections.addAll(jsonArray, grantTypes);
            paramMap.put(OktaConstants.CLIENT_GRANT_TYPES, jsonArray);
        } else {
            handleException("Mandatory parameter grant_types is missing");
        }

        Object clientPostLogoutRedirectUris = oAuthApplicationInfo.getParameter(
                OktaConstants.CLIENT_POST_LOGOUT_REDIRECT_URIS);
        if (clientPostLogoutRedirectUris != null) {
            String[] postLogoutRedirectUris = ((String) clientPostLogoutRedirectUris).split(",");
            JSONArray jsonArray = new JSONArray();
            Collections.addAll(jsonArray, postLogoutRedirectUris);
            paramMap.put(OktaConstants.CLIENT_POST_LOGOUT_REDIRECT_URIS, jsonArray);
        }

        String tokenEndpointAuthMethod = (String) oAuthApplicationInfo.getParameter(
                OktaConstants.CLIENT_TOKEN_ENDPOINT_AUTH_METHOD);
        if (StringUtils.isNotEmpty(tokenEndpointAuthMethod)) {
            paramMap.put(OktaConstants.CLIENT_TOKEN_ENDPOINT_AUTH_METHOD, tokenEndpointAuthMethod);
        } else {
            handleException("Mandatory parameter token_endpoint_auth_method is missing");
        }

        String clientUri = (String) oAuthApplicationInfo.getParameter(OktaConstants.CLIENT_URI);
        if (StringUtils.isNotEmpty(clientUri)) {
            paramMap.put(OktaConstants.CLIENT_URI, clientUri);
        }

        String logoUri = (String) oAuthApplicationInfo.getParameter(OktaConstants.CLIENT_LOGO_URI);
        if (StringUtils.isNotEmpty(logoUri)) {
            paramMap.put(OktaConstants.CLIENT_LOGO_URI, logoUri);
        }

        String initiateLoginUri = (String) oAuthApplicationInfo.getParameter(OktaConstants.CLIENT_INITIATE_LOGIN_URI);
        if (StringUtils.isNotEmpty(initiateLoginUri)) {
            paramMap.put(OktaConstants.CLIENT_INITIATE_LOGIN_URI, initiateLoginUri);
        }

        String applicationType = (String) oAuthApplicationInfo.getParameter(OktaConstants.CLIENT_APPLICATION_TYPE);
        if (StringUtils.isNotEmpty(applicationType)) {
            paramMap.put(OktaConstants.CLIENT_APPLICATION_TYPE, applicationType);
        } else {
            handleException("Mandatory parameter application_type is missing");
        }

        return JSONObject.toJSONString(paramMap);
    }

    /**
     * This method will create {@code OAuthApplicationInfo} object from a Map of Attributes.
     *
     * @param responseMap Response returned from server as a Map
     * @return OAuthApplicationInfo object will return.
     */
    private OAuthApplicationInfo createOAuthAppInfoFromResponse(Map responseMap) {
        if (log.isDebugEnabled()) {
            log.debug("Create OAuth App Info From Response.");
        }
        OAuthApplicationInfo appInfo = new OAuthApplicationInfo();

        appInfo.setClientId((String) responseMap.get(OktaConstants.CLIENT_ID));
        appInfo.setClientSecret((String) responseMap.get(OktaConstants.CLIENT_SECRET));
        appInfo.setClientName((String) responseMap.get(OktaConstants.CLIENT_NAME));
        JSONArray callbackUrl = (JSONArray) responseMap.get(OktaConstants.CLIENT_REDIRECT_URIS);
        if (callbackUrl != null) {
            appInfo.setCallBackURL((String) callbackUrl.toArray()[0]);
        }
        Object clientIdIssuedAt = responseMap.get(OktaConstants.CLIENT_ID_ISSUED_AT);
        if (clientIdIssuedAt != null) {
            appInfo.addParameter(OktaConstants.CLIENT_ID_ISSUED_AT, clientIdIssuedAt);
        }
        Object clientSecretExpiresAt = responseMap.get(OktaConstants.CLIENT_SECRET_EXPIRES_AT);
        if (clientSecretExpiresAt != null) {
            appInfo.addParameter(OktaConstants.CLIENT_SECRET_EXPIRES_AT, clientSecretExpiresAt);
        }
        Object clientUri = responseMap.get(OktaConstants.CLIENT_URI);
        if (clientUri != null) {
            appInfo.addParameter(OktaConstants.CLIENT_URI, clientUri);
        }
        Object logoUri = responseMap.get(OktaConstants.CLIENT_LOGO_URI);
        if (logoUri != null) {
            appInfo.addParameter(OktaConstants.CLIENT_LOGO_URI, logoUri);
        }
        Object applicationType = responseMap.get(OktaConstants.CLIENT_APPLICATION_TYPE);
        if (applicationType != null) {
            appInfo.addParameter(OktaConstants.CLIENT_APPLICATION_TYPE, applicationType);
        }
        Object postLogoutRedirectUris = responseMap.get(OktaConstants.CLIENT_POST_LOGOUT_REDIRECT_URIS);
        if (postLogoutRedirectUris != null) {
            appInfo.addParameter(OktaConstants.CLIENT_POST_LOGOUT_REDIRECT_URIS, postLogoutRedirectUris);
        }
        Object responseTypes = responseMap.get(OktaConstants.CLIENT_RESPONSE_TYPES);
        if (responseTypes != null) {
            appInfo.addParameter(OktaConstants.CLIENT_RESPONSE_TYPES, responseTypes);
        }
        Object grantTypes = responseMap.get(OktaConstants.CLIENT_GRANT_TYPES);
        if (grantTypes != null) {
            appInfo.addParameter(OktaConstants.CLIENT_GRANT_TYPES, grantTypes);
        }
        Object tokenEndpointAuthMethod = responseMap.get(OktaConstants.CLIENT_TOKEN_ENDPOINT_AUTH_METHOD);
        if (tokenEndpointAuthMethod != null) {
            appInfo.addParameter(OktaConstants.CLIENT_TOKEN_ENDPOINT_AUTH_METHOD, tokenEndpointAuthMethod);
        }
        Object initiateLoginUri = responseMap.get(OktaConstants.CLIENT_INITIATE_LOGIN_URI);
        if (initiateLoginUri != null) {
            appInfo.addParameter(OktaConstants.CLIENT_INITIATE_LOGIN_URI, initiateLoginUri);
        }

        return appInfo;
    }

    /**
     * Revokes an access token.
     *
     * @param clientId     clientId of the oauth client
     * @param clientSecret clientSecret of the oauth client
     * @param accessToken  token being revoked
     * @throws APIManagementException This is the custom exception class for API management.
     */
    private void revokeAccessToken(String clientId, String clientSecret, String accessToken) throws APIManagementException {
        if (log.isDebugEnabled()) {
            log.debug("Revoke access token from Authorization Server");
        }

        CloseableHttpClient httpClient = HttpClientBuilder.create().build();
        if (StringUtils.isEmpty(clientId)) {
            handleException("Consumer Key can't be empty.");
        }
        if (StringUtils.isEmpty(clientSecret)) {
            handleException("Consumer Secret can't be empty.");
        }
        if (StringUtils.isEmpty(accessToken)) {
            handleException("Access Token can't be empty.");
        }

        try {
            List<NameValuePair> nvps = new ArrayList<NameValuePair>();
            nvps.add(new BasicNameValuePair(OktaConstants.TOKEN, accessToken));
            nvps.add(new BasicNameValuePair(OktaConstants.TOKEN_TYPE_HINT, OktaConstants.ACCESS_TOKEN));

            String oktaInstanceUrl = configuration.getParameter(OktaConstants.OKTA_INSTANCE_URL);
            String authorizationServerId = configuration.getParameter(OktaConstants.OKTA_AUTHORIZATION_SERVER_ID);

            HttpPost httpPost = new HttpPost(oktaInstanceUrl + "/oauth2/" + authorizationServerId + "/v1/revoke");
            httpPost.setEntity(new UrlEncodedFormEntity(nvps));
            String encodedCredentials;
            try {
                encodedCredentials = Base64.getEncoder().encodeToString((clientId + ":" + clientSecret)
                        .getBytes(OktaConstants.UTF_8));
            } catch (UnsupportedEncodingException e) {
                throw new APIManagementException("Unsupported encoding: ", e);
            }

            httpPost.setHeader(OktaConstants.AUTHORIZATION, OktaConstants.AUTHENTICATION_BASIC + encodedCredentials);
            if (log.isDebugEnabled()) {
                log.debug("Invoking HTTP request to revoke access token");
            }

            HttpResponse response = httpClient.execute(httpPost);
            int statusCode = response.getStatusLine().getStatusCode();
            if (statusCode == HttpStatus.SC_OK) {
                log.info("OAuth accessToken has been successfully revoked");
            } else {
                handleException("Problem occurred while revoking the accesstoken for Consumer Key " + clientId);
            }
        } catch (UnsupportedEncodingException e) {
            handleException("The Character Encoding is not supported. " + e.getMessage(), e);
        } catch (ClientProtocolException e) {
            handleException("HTTP request error has occurred while sending request to OAuth Provider. " +
                    e.getMessage(), e);
        } catch (IOException e) {
            handleException("Error has occurred while reading or closing buffer reader. " + e.getMessage(), e);
        } finally {
            try {
                if (httpClient != null) {
                    httpClient.close();
                }
            } catch (IOException e) {
                log.error(e);
            }
        }
    }

    /**
     * Gets an access token.
     *
     * @param clientId     clientId of the oauth client.
     * @param clientSecret clientSecret of the oauth client.
     * @param parameters   list of request parameters.
     * @return an {@code JSONObject}
     * @throws APIManagementException This is the custom exception class for API management.
     */
    private JSONObject getAccessToken(String clientId, String clientSecret, List<NameValuePair> parameters) throws
            APIManagementException {
        CloseableHttpClient httpClient = HttpClientBuilder.create().build();
        BufferedReader reader = null;

        try {
            String oktaInstanceUrl = configuration.getParameter(OktaConstants.OKTA_INSTANCE_URL);
            String authorizationServerId = configuration.getParameter(OktaConstants.OKTA_AUTHORIZATION_SERVER_ID);
            HttpPost httpPost = new HttpPost(oktaInstanceUrl + "/oauth2/" + authorizationServerId + "/v1/token");
            httpPost.setEntity(new UrlEncodedFormEntity(parameters));
            String encodedCredentials;
            try {
                encodedCredentials = Base64.getEncoder().encodeToString((clientId + ":" + clientSecret)
                        .getBytes(OktaConstants.UTF_8));
            } catch (UnsupportedEncodingException e) {
                throw new APIManagementException("Unsupported encoding: ", e);
            }
            httpPost.setHeader(OktaConstants.AUTHORIZATION, OktaConstants.AUTHENTICATION_BASIC + encodedCredentials);
            if (log.isDebugEnabled()) {
                log.debug("Invoking HTTP request to get the accesstoken");
            }
            HttpResponse response = httpClient.execute(httpPost);
            int statusCode = response.getStatusLine().getStatusCode();
            HttpEntity entity = response.getEntity();
            reader = new BufferedReader(new InputStreamReader(entity.getContent(), OktaConstants.UTF_8));
            JSONObject responseJSON = getParsedObjectByReader(reader);

            if (HttpStatus.SC_OK == statusCode) {
                if (responseJSON != null) {
                    log.info("JSON response after getting new access token: " + responseJSON.toJSONString());
                    return responseJSON;
                }
            } else {
                log.error("Failed to get accessToken for clientId " + clientId + " JSON Response: " +
                        responseJSON.toJSONString());
            }
        } catch (UnsupportedEncodingException e) {
            handleException("The Character Encoding is not supported. " + e.getMessage(), e);
        } catch (ParseException e) {
            handleException("Error while parsing response json " + e.getMessage(), e);
        } catch (IOException e) {
            handleException("Error has occurred while reading or closing buffer reader. " + e.getMessage(), e);
        } finally {
            closeResources(reader, httpClient);
        }
        return null;
    }

    /**
     * Update the access token info after getting new access token.
     *
     * @param tokenInfo    Token info need to be updated.
     * @param responseJSON AccessTokenInfo
     * @return AccessTokenInfo
     */
    private AccessTokenInfo updateTokenInfo(AccessTokenInfo tokenInfo, JSONObject responseJSON) {
        if (log.isDebugEnabled()) {
            log.debug("Update the access token info after getting new access token.");
        }
        tokenInfo.setAccessToken((String) responseJSON.get(OktaConstants.ACCESS_TOKEN));
        Long expireTime = (Long) responseJSON.get(OktaConstants.ACCESS_TOKEN_EXPIRES_IN);

        if (expireTime == null) {
            tokenInfo.setTokenValid(false);
            tokenInfo.setErrorcode(APIConstants.KeyValidationStatus.API_AUTH_INVALID_CREDENTIALS);
            return tokenInfo;
        }
        tokenInfo.setValidityPeriod(expireTime);

        String tokenScopes = (String) responseJSON.get(OktaConstants.ACCESS_TOKEN_SCOPE);
        if (StringUtils.isNotEmpty(tokenScopes)) {
            tokenInfo.setScope(tokenScopes.split("\\s+"));
        }

        tokenInfo.setTokenValid(Boolean.parseBoolean(OktaConstants.ACCESS_TOKEN_ACTIVE));
        tokenInfo.setTokenState(OktaConstants.ACCESS_TOKEN_ACTIVE);

        return tokenInfo;
    }

    /**
     * Resource deallocation of BufferedReader and CloseableHttpClient.
     *
     * @param reader BufferedReader.
     * @param httpClient CloseableHttpClient.
     */
    private void closeResources(BufferedReader reader, CloseableHttpClient httpClient) {
        if (reader != null) {
            IOUtils.closeQuietly(reader);
        }
        try {
            if (httpClient != null) {
                httpClient.close();
            }
        } catch (IOException e) {
            log.error(e);
        }
    }

    /**
     * Returns a space separate string from list of the contents in the string array.
     *
     * @param stringArray an array of strings.
     * @return space separated string.
     */
    private static String convertToString(String[] stringArray) {
        if (stringArray != null) {
            StringBuilder sb = new StringBuilder();
            List<String> strList = Arrays.asList(stringArray);
            for (String s : strList) {
                sb.append(s);
                sb.append(" ");
            }

            return sb.toString().trim();
        }

        return null;
    }

    /**
     * Can be used to parse {@code BufferedReader} object that are taken from response stream, to a {@code JSONObject}.
     *
     * @param reader {@code BufferedReader} object from response.
     * @return JSON payload as a name value map.
     */
    private JSONObject getParsedObjectByReader(BufferedReader reader) throws ParseException, IOException {
        JSONObject parsedObject = null;
        JSONParser parser = new JSONParser();
        if (reader != null) {
            parsedObject = (JSONObject) parser.parse(reader);
        }

        return parsedObject;
    }

    /**
     * Common method to throw exceptions. This will only expect one parameter.
     *
     * @param msg error message as a string.
     * @throws APIManagementException This is the custom exception class for API management.
     */
    private void handleException(String msg) throws APIManagementException {
        log.error(msg);
        throw new APIManagementException(msg);
    }

    /**
     * Common method to throw exceptions.
     *
     * @param msg this parameter contain error message that we need to throw.
     * @param e   Exception object.
     * @throws APIManagementException This is the custom exception class for API management
     */
    private void handleException(String msg, Exception e) throws APIManagementException {
        log.error(msg, e);
        throw new APIManagementException(msg, e);
    }
}