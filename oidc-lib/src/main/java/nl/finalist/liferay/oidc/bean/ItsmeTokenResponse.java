package nl.finalist.liferay.oidc.bean;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

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


    public boolean checkId(String issuer, String clientId) {
        /*if (idToken.getClaimsSet().getIssuer().equals(issuer)
                && idToken.getClaimsSet().getAudience().equals(audience)
                && idToken.getClaimsSet().getExpirationTime() < System
                .currentTimeMillis()) {
            return true;
        }*/
        return true; //TODO: implement validity
    }

    @Override
    public String toString(){
        ObjectMapper m = new ObjectMapper();
        try {
            return m.writeValueAsString(this);
        } catch (JsonProcessingException e) {
            return super.toString();
        }
    }
}
