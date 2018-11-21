package nl.finalist.liferay.oidc;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import nl.finalist.liferay.oidc.bean.ItsmeTokenResponse;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.http.NameValuePair;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.message.BasicNameValuePair;
import org.apache.oltu.oauth2.client.OAuthClient;
import org.apache.oltu.oauth2.client.URLConnectionClient;
import org.apache.oltu.oauth2.client.request.OAuthBearerClientRequest;
import org.apache.oltu.oauth2.client.request.OAuthClientRequest;
import org.apache.oltu.oauth2.client.response.OAuthResourceResponse;
import org.apache.oltu.oauth2.common.OAuth;
import org.apache.oltu.oauth2.common.exception.OAuthProblemException;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.apache.oltu.oauth2.common.message.types.GrantType;

import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.util.*;

/**
 * Servlet filter that initiates OpenID Connect logins, and handles the resulting flow, until and including the
 * UserInfo request. It saves the UserInfo in a session attribute, to be examined by an AutoLogin.
 *
 * @author Gunther Verhemeldonck, GFI Belux
 */
public class LibFilter {

    private static final String REQ_PARAM_CODE = "code";
    private static final String REQ_PARAM_STATE = "state";
    private ObjectMapper mapper = new ObjectMapper();

    /**
     * Property that is used to configure whether to enable OpenID Connect auth
     */
    public static final String PROPKEY_ENABLE_OPEN_IDCONNECT = "openidconnect.enableOpenIDConnect";

    public enum FilterResult {
        CONTINUE_CHAIN,
        BREAK_CHAIN;
    }


    /**
     * Session attribute name containing the UserInfo
     */
    public static final String OPENID_CONNECT_SESSION_ATTR = "OpenIDConnectUserInfo";


    private final LiferayAdapter liferay;

    public LibFilter(LiferayAdapter liferay) {
        this.liferay = liferay;
    }


    /**
     * Filter the request.
     * <br><br>LOGIN:<br>
     * The first time this filter gets hit, it will redirect to the OP.
     * Second time it will expect a code and state param to be set, and will exchange the code for an access token.
     * Then it will request the UserInfo given the access token.
     * <br>--
     * Result: the OpenID Connect 1.0 flow.
     * <br><br>LOGOUT:<br>
     * When the filter is hit and according values for SSO logout are set, it will redirect to the OP logout resource.
     * From there the request should be redirected "back" to a public portal page or the public portal home page.
     *
     * @param request     the http request
     * @param response    the http response
     * @param filterChain the filterchain
     * @return FilterResult, to be able to distinct between continuing the chain or breaking it.
     * @throws Exception according to interface.
     */
    protected FilterResult processFilter(HttpServletRequest request, HttpServletResponse response, FilterChain
            filterChain) throws Exception {

        OIDCConfiguration oidcConfiguration = liferay.getOIDCConfiguration(liferay.getCompanyId(request));

        // If the plugin is not enabled, short circuit immediately
        if (!oidcConfiguration.isEnabled()) {
            liferay.trace("OpenIDConnectFilter not enabled. Will skip it.");
            return FilterResult.CONTINUE_CHAIN;
        }

        liferay.trace("In processFilter()...");

        String pathInfo = request.getPathInfo();

        if (null != pathInfo) {
            if (pathInfo.contains("/portal/login")) {
                if (!StringUtils.isBlank(request.getParameter(REQ_PARAM_CODE))
                        && !StringUtils.isBlank(request.getParameter(REQ_PARAM_STATE))) {

                    if (!isUserLoggedIn(request)) {
                        // LOGIN: Second time it will expect a code and state param to be set, and will exchange the code for an access token.
                        liferay.trace("About to exchange code for access token");
                        exchangeCodeForAccessToken(request);
                    } else {
                        liferay.trace("subsequent run into filter during openid conversation, but already logged in." +
                                "Will not exchange code for token twice.");
                    }
                } else {
                    // LOGIN: The first time this filter gets hit, it will redirect to the OP.
                    liferay.trace("About to redirect to OpenID Provider");
                    redirectToLogin(request, response, oidcConfiguration.clientId());
                    // no continuation of the filter chain; we expect the redirect to commence.
                    return FilterResult.BREAK_CHAIN;
                }
            } else if (pathInfo.contains("/portal/logout")) {
                final String ssoLogoutUri = oidcConfiguration.ssoLogoutUri();
                final String ssoLogoutParam = oidcConfiguration.ssoLogoutParam();
                final String ssoLogoutValue = oidcConfiguration.ssoLogoutValue();
                if (null != ssoLogoutUri && ssoLogoutUri.length
                        () > 0 && isUserLoggedIn(request)) {

                    liferay.trace("About to logout from SSO by redirect to " + ssoLogoutUri);
                    // LOGOUT: If Portal Logout URL is requested, redirect to OIDC Logout resource afterwards to globally logout.
                    // From there, the request should be redirected back to the Liferay portal home page.
                    request.getSession().invalidate();
                    redirectToLogout(request, response, ssoLogoutUri, ssoLogoutParam, ssoLogoutValue);
                    // no continuation of the filter chain; we expect the redirect to commence.
                    return FilterResult.BREAK_CHAIN;
                }
            }
        }
        // continue chain
        return FilterResult.CONTINUE_CHAIN;
    }

    // STEP 1
    private void redirectToLogin(HttpServletRequest request, HttpServletResponse response, String clientId) throws
            IOException {
        OIDCConfiguration oidcConfiguration = liferay.getOIDCConfiguration(liferay.getCompanyId(request));

        try {
            //TODO: see https://belgianmobileid.github.io/slate/login.html#3-2-forging-an-authentication-request
            //TODO: no support for NONCE in the OLTU api, while being suggested by Itsme !!
            liferay.trace("SCOPE: " + oidcConfiguration.scope());
            OAuthClientRequest oAuthRequest = OAuthClientRequest
                    .authorizationLocation(oidcConfiguration.authorizationLocation())
                    .setClientId(clientId)
                    .setRedirectURI(getRedirectUri(request))
                    .setResponseType("code")
                    .setScope(oidcConfiguration.scope())
                    .setState(generateStateParam(request))
                    .buildQueryMessage();
            liferay.debug("Redirecting to URL: " + oAuthRequest.getLocationUri());
            response.sendRedirect(oAuthRequest.getLocationUri());
        } catch (OAuthSystemException e) {
            throw new IOException("While redirecting to OP for SSO login", e);
        }
    }

    // STEP 2
    private void exchangeCodeForAccessToken(HttpServletRequest request) throws IOException, ParseException {
        OIDCConfiguration config = liferay.getOIDCConfiguration(liferay.getCompanyId(request));

        // Load key configuration
        JWKSet privateJwkSet = JWKSet.load(new URL(config.privateJwkSetEndPoint()));
        JWKSet publicJwkSet = JWKSet.load(new URL(config.publicJwkSetEndPoint()));

        try {
            String stateParam = request.getParameter(REQ_PARAM_STATE);

            String expectedState = generateStateParam(request);
            if (!expectedState.equals(stateParam)) {
                liferay.info("Provided state parameter '" + stateParam + "' does not equal expected '"
                        + expectedState + "', cannot continue.");
                throw new IOException("Invalid state parameter");
            }

            ItsmeTokenResponse itsmeTokenResponse = fetchAuthenticationToken(request, config, privateJwkSet, publicJwkSet);

            if (!itsmeTokenResponse.validIdToken(config.issuer(), config.clientId())) {
                liferay.warn("The token was not valid: " + itsmeTokenResponse);
                return;
            }

            final Map<String, Object> openIDUserInfo = getClaims(itsmeTokenResponse, config, privateJwkSet, publicJwkSet);
            final String subject = (String) openIDUserInfo.get("sub");
            if (!itsmeTokenResponse.matchingSubjects(subject)){
                liferay.error("Invalid subject in userInfo response [" + subject + "]!");
                return;
            }

            request.getSession().setAttribute(OPENID_CONNECT_SESSION_ATTR, openIDUserInfo);

        } catch (OAuthSystemException | OAuthProblemException e) {
            throw new IOException("While exchanging code for access token and retrieving user info", e);
        } catch (ParseException | JOSEException e) {
            throw new IOException("Error signing JWT", e);
        }
    }

    private ItsmeTokenResponse fetchAuthenticationToken(HttpServletRequest request, OIDCConfiguration oidcConfiguration,
                                                        JWKSet priv, JWKSet pub) throws IOException, ParseException, JOSEException {
        try (CloseableHttpClient client = HttpClients.createDefault()) {
            HttpPost httpPost = new HttpPost(oidcConfiguration.tokenLocation());

            List<NameValuePair> params = new ArrayList<>();

            params.add(new BasicNameValuePair("grant_type", GrantType.AUTHORIZATION_CODE.toString()));
            params.add(new BasicNameValuePair("code", request.getParameter(REQ_PARAM_CODE)));
            params.add(new BasicNameValuePair("redirect_uri", getRedirectUri(request)));
            params.add(new BasicNameValuePair("client_assertion", constructPrivateKeyJWT(oidcConfiguration.clientId(),
                    oidcConfiguration.tokenLocation(), priv)));
            params.add(new BasicNameValuePair("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"));

            httpPost.setEntity(new UrlEncodedFormEntity(params));

            CloseableHttpResponse response = client.execute(httpPost);
            final String jsonResponse = IOUtils.toString(response.getEntity().getContent(), "UTF-8");
            ItsmeTokenResponse itsmeTokenResponse = mapper.readValue(jsonResponse, ItsmeTokenResponse.class);
            itsmeTokenResponse.setIdTokenJwt(decryptToken(itsmeTokenResponse.getIdToken(), oidcConfiguration, priv, pub));
            itsmeTokenResponse.setLoggingAdapter(liferay);
            return itsmeTokenResponse;
        }
    }

    private String constructPrivateKeyJWT(String clientId, String tokenEndPoint, JWKSet jwkSet) throws JOSEException {
        final Calendar now = Calendar.getInstance();
        now.add(Calendar.MINUTE, 3);
        final Date expirationDate = now.getTime();

        RSAKey signKey = (RSAKey) jwkSet.getKeyByKeyId("s1");
        JWTClaimsSet jwtClaimsSet = new JWTClaimsSet.Builder()
                .issuer(clientId)
                .subject(clientId)
                .audience(Collections.singletonList(tokenEndPoint))
                .jwtID(UUID.randomUUID().toString())
                .expirationTime(expirationDate)
                .build();

        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256).keyID("s1").build();
        SignedJWT signedToken = new SignedJWT(header, jwtClaimsSet);
        JWSSigner signer = new RSASSASigner(signKey);
        signedToken.sign(signer);
        return signedToken.serialize();
    }


    // STEP 3
    private Map<String, Object> getClaims(ItsmeTokenResponse tokenResponse, OIDCConfiguration config, JWKSet priv,
                                          JWKSet pub) throws ParseException, JOSEException, OAuthProblemException, OAuthSystemException {

        OAuthClient oAuthClient = new OAuthClient(new URLConnectionClient());
        OAuthClientRequest userInfoRequest = new OAuthBearerClientRequest(config.profileUri())
                .setAccessToken(tokenResponse.getAccessToken()).buildHeaderMessage();

        final OAuthResourceResponse userInfoResponse =
                oAuthClient.resource(userInfoRequest, OAuth.HttpMethod.GET, OAuthResourceResponse.class);
        SignedJWT signedJWT = decryptToken(userInfoResponse.getBody(), config, priv, pub);
        Map<String, Object> openIDUserInfo = new HashMap<>();

        for (Map.Entry<String, Object> entry : signedJWT.getJWTClaimsSet().getClaims().entrySet()) {
            openIDUserInfo.put(entry.getKey(), entry.getValue());
        }

        return openIDUserInfo;
    }

    private SignedJWT decryptToken(final String token, OIDCConfiguration config, JWKSet priv, JWKSet pub) throws ParseException, JOSEException {
        RSAKey decryptKey = (RSAKey) priv.getKeyByKeyId("e1");
        RSAKey verifyKey = (RSAKey) pub.getKeyByKeyId("s1");
        JWEObject jweObject = JWEObject.parse(token);
        jweObject.decrypt(new RSADecrypter(decryptKey));
        SignedJWT signedJWT = jweObject.getPayload().toSignedJWT();
        signedJWT.verify(new RSASSAVerifier(verifyKey));
        return signedJWT;
    }


    protected void redirectToLogout(HttpServletRequest request, HttpServletResponse response,
                                    String logoutUrl, String logoutUrlParamName, String logoutUrlParamValue) throws
            IOException {
        // build logout URL and append params if present
        if (StringUtils.isNotEmpty(logoutUrlParamName) && StringUtils.isNotEmpty(logoutUrlParamValue)) {
            logoutUrl = addParameter(logoutUrl, logoutUrlParamName, logoutUrlParamValue);
        }
        liferay.debug("On " + request.getRequestURL() + " redirect to OP for SSO logout: " + logoutUrl);
        response.sendRedirect(logoutUrl);
    }

    protected String getRedirectUri(HttpServletRequest request) {
        String completeURL = liferay.getCurrentCompleteURL(request);
        // remove parameters
        return completeURL.replaceAll("\\?.*", "");
    }

    // TODO: See https://belgianmobileid.github.io/slate/login.html#3-2-forging-an-authentication-request
    // TODO: the State param based on just the sessionID might be too simple! (encrypt client id with session Id?)
    protected String generateStateParam(HttpServletRequest request) {
        return DigestUtils.md5Hex(request.getSession().getId());
    }

    protected boolean isUserLoggedIn(HttpServletRequest request) {
        return liferay.isUserLoggedIn(request);
    }

    protected String addParameter(String url, String param, String value) {
        String anchor = "";
        int posOfAnchor = url.indexOf('#');
        if (posOfAnchor > -1) {
            anchor = url.substring(posOfAnchor);
            url = url.substring(0, posOfAnchor);
        }

        StringBuffer sb = new StringBuffer();
        sb.append(url);
        if (url.indexOf('?') < 0) {
            sb.append('?');
        } else if (!url.endsWith("?") && !url.endsWith("&")) {
            sb.append('&');
        }
        sb.append(param);
        sb.append('=');
        try {
            sb.append(URLEncoder.encode(value, StandardCharsets.UTF_8.toString()));
        } catch (UnsupportedEncodingException e) {
            sb.append(value);
        }
        sb.append(anchor);

        return sb.toString() + anchor;
    }

}
