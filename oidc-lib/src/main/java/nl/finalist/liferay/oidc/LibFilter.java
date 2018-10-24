package nl.finalist.liferay.oidc;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.impl.Base64UrlCodec;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.lang3.StringUtils;
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
import java.math.BigInteger;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;
import java.util.*;

/**
 * Servlet filter that initiates OpenID Connect logins, and handles the resulting flow, until and including the
 * UserInfo request. It saves the UserInfo in a session attribute, to be examined by an AutoLogin.
 * <p>
 * This class is adapted for ITSME integration.
 *
 * @author Gunther Verhemeldonck, Gfi nv
 */
public class LibFilter {

    public static final String REQ_PARAM_CODE = "code";
    public static final String REQ_PARAM_STATE = "state";

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
            liferay.trace("OpenIDConnectFilter not enabled for this virtual instance. Will skip it.");
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

    protected void exchangeCodeForAccessToken(HttpServletRequest request) throws IOException {
        OIDCConfiguration oidcConfiguration = liferay.getOIDCConfiguration(liferay.getCompanyId(request));

        try {
            String stateParam = request.getParameter(REQ_PARAM_STATE);

            String expectedState = generateStateParam(request);
            if (!expectedState.equals(stateParam)) {
                liferay.info("Provided state parameter '" + stateParam + "' does not equal expected '"
                        + expectedState + "', cannot continue.");
                throw new IOException("Invalid state parameter");
            }

            OAuthClientRequest tokenRequest = buildClientRequest(request, oidcConfiguration);
            liferay.debug("Token request to uri: " + tokenRequest.getLocationUri());

            OAuthClient oAuthClient = new OAuthClient(new URLConnectionClient());
            OpenIdConnectResponse oAuthResponse = oAuthClient.accessToken(tokenRequest, OpenIdConnectResponse.class);
            liferay.trace("Access/id token response: " + oAuthResponse);
            String accessToken = oAuthResponse.getAccessToken();

            if (!oAuthResponse.checkId(oidcConfiguration.issuer(), oidcConfiguration.clientId())) {
                liferay.warn("The token was not valid: " + oAuthResponse.toString());
                return;
            }

            // The only API to be enabled (in case of Google) is Google+.
            OAuthClientRequest userInfoRequest = new OAuthBearerClientRequest(oidcConfiguration.profileUri())
                    .setAccessToken(accessToken).buildHeaderMessage();
            liferay.trace("UserInfo request to uri: " + userInfoRequest.getLocationUri());
            OAuthResourceResponse userInfoResponse =
                    oAuthClient.resource(userInfoRequest, OAuth.HttpMethod.GET, OAuthResourceResponse.class);

            liferay.debug("Response from UserInfo request: " + userInfoResponse.getBody());
            Map openIDUserInfo = new ObjectMapper().readValue(userInfoResponse.getBody(), HashMap.class);

            liferay.debug("Setting OpenIDUserInfo object in session: " + openIDUserInfo);
            request.getSession().setAttribute(OPENID_CONNECT_SESSION_ATTR, openIDUserInfo);

        } catch (OAuthSystemException | OAuthProblemException e) {
            throw new IOException("While exchanging code for access token and retrieving user info", e);
        }
    }

    protected OAuthClientRequest buildClientRequest(HttpServletRequest request, OIDCConfiguration oidcConfiguration) throws OAuthSystemException {
        final String code = request.getParameter(REQ_PARAM_CODE);
        liferay.debug("Constructing itsme OAuthClientRequest instance with code [" + code + "]...");
        try {
            return OAuthClientRequest.tokenLocation(oidcConfiguration.tokenLocation())
                    .setGrantType(GrantType.AUTHORIZATION_CODE)
                    .setCode(code)
                    .setRedirectURI(getRedirectUri(request))
                    .setAssertion(constructPrivateKeyJWT(oidcConfiguration.clientId(), oidcConfiguration.tokenLocation())) //GFI | Itsme Customized
                    .setAssertionType("urn:ietf:params:oauth:client-assertion-type:jwt-bearer") //GFI | Itsme Customized
                    .buildBodyMessage();
        } catch (Exception e) {
            throw new OAuthSystemException("Failed to sign JWT", e);
        }
    }

    //GFI | Itsme Custom
    protected String constructPrivateKeyJWT(String clientId, String tokenEndPoint) throws UnsupportedEncodingException, NoSuchAlgorithmException, InvalidKeySpecException {
        liferay.debug("Constructing and signing itsme client_assertion JWT ...");
        final String jit = UUID.randomUUID().toString();
        final Calendar now = Calendar.getInstance();
        now.add(Calendar.MINUTE, 3);
        final Date expirationDate = now.getTime();


        BigInteger modulus = new BigInteger(1, Base64UrlCodec.BASE64URL.decode("pJADu0nyhCrh9XIRTO42V6YQqAeNABGGo006hknHw86wYByjHMhpYYwHuxuyx44mO8iQIcJkh5NPlkcaDN90RH0JOxyEE1pES5C3LqntC0mAP6BWoqMhY8g4PT2EJyPjVYZcpaZw0VUp6E5kx847dbvhMe8KWy0geuCwrCgXVhWDRoIyV7r2k948zlmRJjbdjkNosYEFI43nicZ_jckTbs_8nzlxDQo8GtstdhR_oUbXyyBJM66SUA8KxWV6NG0zubNIYWxHIwlU938gdpTNfUMKm78f78iPyfuoPz2dTb6Z7OP7WZb06eRv41i_dS0Zh-sKKHrpUYXRf6VrOoU96w"));
        BigInteger exponent = new BigInteger(1, Base64UrlCodec.BASE64URL.decode("AQAB"));
        Key key = KeyFactory.getInstance("RSA").generatePrivate(new RSAPrivateKeySpec(modulus, exponent));

        String jwt = Jwts.builder()
                .setHeaderParam("typ", "JWT")
                .setIssuer(clientId)
                .setSubject(clientId)
                .setAudience(tokenEndPoint)
                .setId(jit)
                .setExpiration(expirationDate)
                .signWith(SignatureAlgorithm.RS256, key).compact();

        liferay.debug(jwt);
        return jwt;
    }

    protected void redirectToLogin(HttpServletRequest request, HttpServletResponse response, String clientId) throws
            IOException {
        OIDCConfiguration oidcConfiguration = liferay.getOIDCConfiguration(liferay.getCompanyId(request));

        try {
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
