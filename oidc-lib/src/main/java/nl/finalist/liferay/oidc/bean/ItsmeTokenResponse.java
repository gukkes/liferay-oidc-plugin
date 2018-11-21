package nl.finalist.liferay.oidc.bean;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jwt.SignedJWT;
import nl.finalist.liferay.oidc.LiferayAdapter;

import java.text.ParseException;
import java.util.Date;

/**
 * Value object.
 *
 * @author Gunther Verhemeldonck, Gfi Belux
 */
public class ItsmeTokenResponse {

    @JsonProperty("access_token")
    private String accessToken;

    @JsonProperty("token_type")
    private String tokenType;

    @JsonProperty("expire_in")
    private int expireIn;

    @JsonProperty("id_token")
    private String idToken;

    @JsonIgnore
    private SignedJWT idTokenJwt;

    @JsonIgnore
    private LiferayAdapter liferay;

    public String getAccessToken() {
        return accessToken;
    }

    public void setAccessToken(String accessToken) {
        this.accessToken = accessToken;
    }

    public String getTokenType() {
        return tokenType;
    }

    public void setTokenType(String tokenType) {
        this.tokenType = tokenType;
    }

    public int getExpireIn() {
        return expireIn;
    }

    public void setExpireIn(int expireIn) {
        this.expireIn = expireIn;
    }

    public String getIdToken() {
        return idToken;
    }

    public void setIdToken(String idToken) {
        this.idToken = idToken;
    }


    public boolean validIdToken(String issuer, String clientId) throws ParseException {
        if (idTokenJwt == null) {
            liferay.warn("ID Token not found");
            return false;
        }

        if (idTokenJwt.getJWTClaimsSet().getIssuer().equals(issuer) &&
                idTokenJwt.getJWTClaimsSet().getAudience().contains(clientId) &&
                idTokenJwt.getJWTClaimsSet().getExpirationTime().after(new Date())) {
            return true;
        } else {
            //Important: Print out the forgery fields
            if (!idTokenJwt.getJWTClaimsSet().getIssuer().equals(issuer)) {
                liferay.warn("ID Token forgery detected! Invalid issuer [" + issuer + "]");
            }
            if (!idTokenJwt.getJWTClaimsSet().getAudience().contains(clientId)) {
                liferay.warn("ID Token forgery detected! Invalid audience [" + clientId + "]");
            }
            if (idTokenJwt.getJWTClaimsSet().getExpirationTime().before(new Date())){
                liferay.warn("ID Token forgery detected! Token expired.");
            }
            return false;
        }
    }

    @Override
    public String toString() {
        ObjectMapper m = new ObjectMapper();
        try {
            return m.writeValueAsString(this);
        } catch (JsonProcessingException e) {
            return super.toString();
        }
    }

    public void setIdTokenJwt(SignedJWT jwt) {
        this.idTokenJwt = jwt;
    }

    public void setLoggingAdapter(LiferayAdapter liferay) {
        this.liferay = liferay;
    }

    private String getSubject() throws ParseException {
        if (idTokenJwt == null) {
            liferay.warn("ID Token not found");
            return "---x---"; //unknown value
        }
       return idTokenJwt.getJWTClaimsSet().getSubject();
    }

    // Security check !
    // Itmse best practice to validate the subject (https://belgianmobileid.github.io/slate/login.html#3-7-obtaining-user-attributes-or-claims)
    public boolean matchingSubjects(String subject) throws ParseException {
        return subject != null && subject.equals(this.getSubject());
    }
}
