package org.wso2.carbon.identity.authenticator.basecamp;

import org.apache.oltu.oauth2.client.OAuthClient;
import org.apache.oltu.oauth2.client.request.OAuthClientRequest;
import org.apache.oltu.oauth2.client.response.OAuthAuthzResponse;
import org.apache.oltu.oauth2.client.response.OAuthClientResponse;
import org.apache.oltu.oauth2.client.response.OAuthJSONAccessTokenResponse;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.Spy;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;
import org.powermock.reflect.Whitebox;
import org.testng.Assert;
import org.testng.IObjectFactory;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.ObjectFactory;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authenticator.oidc.OIDCAuthenticatorConstants;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.net.URL;
import java.util.HashMap;
import java.util.Map;

import static org.mockito.Mockito.when;
import static org.mockito.MockitoAnnotations.initMocks;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;

@RunWith(PowerMockRunner.class)
@PrepareForTest({OAuthAuthzResponse.class, AuthenticatedUser.class,
        OAuthClientRequest.class, URL.class})

public class BasecampAuthenticatorTest {

    @Mock
    OAuthClientResponse oAuthClientResponse;
    @Mock
    HttpServletRequest httpServletRequest;
    @Mock
    OAuthAuthzResponse mockOAuthAuthzResponse;
    @Mock
    private AuthenticatedUser authenticatedUser;
    @Spy
    private AuthenticationContext context = new AuthenticationContext();
    @Mock
    private HttpServletResponse httpServletResponse;

    @Mock
    private OAuthClient mockOAuthClient;

    @Mock
    private OAuthClientRequest mockOAuthClientRequest;
    @Mock
    private OAuthJSONAccessTokenResponse oAuthJSONAccessTokenResponse;

    BasecampAuthenticator basecampAuthenticator;

    @DataProvider(name = "authenticatorProperties")
    public Object[][] getAuthenticatorPropertiesData() {

        Map<String, String> authenticatorProperties = new HashMap<>();
        authenticatorProperties.put(OIDCAuthenticatorConstants.CLIENT_ID, "test-client-id");
        authenticatorProperties.put(OIDCAuthenticatorConstants.CLIENT_SECRET, "test-client-secret");
        authenticatorProperties.put("callbackUrl", "http://localhost:9443/commonauth");
        authenticatorProperties.put("scope", "");
        return new Object[][]{{authenticatorProperties}};
    }

    @ObjectFactory
    public IObjectFactory getObjectFactory() {
        return new org.powermock.modules.testng.PowerMockObjectFactory();
    }

    @BeforeMethod
    public void setUp() {
        basecampAuthenticator = new BasecampAuthenticator();
        initMocks(this);
    }

    @Test(description = "Test case for getTokenEndpoint method", dataProvider = "authenticatorProperties")
    public void testGetTokenEndpoint(
            Map<String, String> authenticatorProperties) {
        String tokenEndpoint = basecampAuthenticator.getTokenEndpoint(authenticatorProperties);
        Assert.assertEquals(BasecampAuthenticatorConstants.BASECAMP_TOKEN_ENDPOINT, tokenEndpoint);
    }

    @Test(description = "Test case for getUserInfoEndpoint method", dataProvider = "authenticatorProperties")
    public void testGetUserInfoEndpoint(
            Map<String, String> authenticatorProperties) {
        String userInfoEndpoint = basecampAuthenticator.getUserInfoEndpoint(oAuthClientResponse, authenticatorProperties);
        Assert.assertEquals(BasecampAuthenticatorConstants.BASECAMP_USERINFO_ENDPOINT, userInfoEndpoint);
    }

    @Test(description = "Test case for requiredIDToken method", dataProvider = "authenticatorProperties")
    public void testRequiredIDToken(Map<String, String> authenticatorProperties) {
        Assert.assertFalse(basecampAuthenticator.requiredIDToken(authenticatorProperties));
    }

    @Test(description = "Test case for getFriendlyName method")
    public void testGetFriendlyName() {
        Assert.assertEquals(BasecampAuthenticatorConstants.AUTHENTICATOR_FRIENDLY_NAME,
                basecampAuthenticator.getFriendlyName());
    }

    @Test(description = "Test case for getAuthorizationServerEndpoint method", dataProvider = "authenticatorProperties")
    public void testGetAuthorizationServerEndpoint(
            Map<String, String> authenticatorProperties) {
        Assert.assertEquals(BasecampAuthenticatorConstants.BASECAMP_OAUTH_ENDPOINT,
                basecampAuthenticator.getAuthorizationServerEndpoint(authenticatorProperties));
    }

    @Test(description = "Test case for getName method")
    public void testGetName() {
        Assert.assertEquals(BasecampAuthenticatorConstants.AUTHENTICATOR_NAME, basecampAuthenticator.getName());
    }

    @Test(description = "Test case for canHandle method")
    public void testCanHandle() {
        Assert.assertNotNull(basecampAuthenticator.canHandle(httpServletRequest));
    }

    @Test(description = "Test case for getConfigurationProperties method")
    public void testGetConfigurationProperties() {
        Assert.assertEquals(3, basecampAuthenticator.getConfigurationProperties().size());
    }

    @Test(expectedExceptions = AuthenticationFailedException.class,
            description = "Test case for processAuthenticationResponse", dataProvider = "authenticatorProperties")
    public void testProcessAuthenticationResponse(
            Map<String, String> authenticatorProperties) throws Exception {

        BasecampAuthenticator spyAuthenticator = PowerMockito.spy(new BasecampAuthenticator());
        PowerMockito.mockStatic(OAuthAuthzResponse.class);
        when(OAuthAuthzResponse.oauthCodeAuthzResponse(Mockito.any(HttpServletRequest.class)))
                .thenReturn(mockOAuthAuthzResponse);
        when(oAuthClientResponse.getParam(OIDCAuthenticatorConstants.ACCESS_TOKEN))
                .thenReturn("test-token");
        PowerMockito.doReturn("{\"token\":\"test-token\",\"id\":\"testuser\"}")
                .when(spyAuthenticator, "sendRequest", Mockito.anyString(), Mockito.anyString());
        PowerMockito.mockStatic(AuthenticatedUser.class);
        when(AuthenticatedUser.createFederateAuthenticatedUserFromSubjectIdentifier(Mockito.anyString()))
                .thenReturn(authenticatedUser);
        context.setAuthenticatorProperties(authenticatorProperties);
        spyAuthenticator.processAuthenticationResponse(httpServletRequest, httpServletResponse, context);
        Assert.assertNotNull(context.getSubject());
    }

    @Test(description = "Test case for getOauthResponse method")
    public void testGetOauthResponse() throws Exception {
        OAuthClientResponse oAuthClientResponse = GetOauthResponse(mockOAuthClient, mockOAuthClientRequest);
        Assert.assertNotNull(oAuthClientResponse);
    }

    public OAuthClientResponse GetOauthResponse(OAuthClient mockOAuthClient, OAuthClientRequest mockOAuthClientRequest)
            throws Exception {
        when(mockOAuthClient.accessToken(mockOAuthClientRequest)).thenReturn(oAuthJSONAccessTokenResponse);
        OAuthClientResponse oAuthClientResponse = Whitebox.invokeMethod(basecampAuthenticator,
                "getOauthResponse", mockOAuthClient, mockOAuthClientRequest);
        return oAuthClientResponse;
    }

    @Test(description = "Test case for InitiateAuthenticationRequest", dataProvider = "authenticatorProperties")
    public void testInitiateAuthenticationRequest(Map<String, String> authenticatorProperties) throws Exception {
        context.setAuthenticatorProperties(authenticatorProperties);
        basecampAuthenticator.
                initiateAuthenticationRequest(httpServletRequest, httpServletResponse, context);
    }

    @Test(description = "Test case for getSubjectAttributes method ", dataProvider = "authenticatorProperties")
    public void testGetSubjectAttributest(Map<String, String> authenticateproperties) throws Exception {
        when(oAuthClientResponse.getParam("access_token")).thenReturn("{token:dummytoken}");
        Map<ClaimMapping, String> claims = basecampAuthenticator.getSubjectAttributes(oAuthClientResponse,
                authenticateproperties);
        Assert.assertEquals(0, claims.size());
    }
}
