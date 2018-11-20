package nl.finalist.liferay.oidc.providers;

import java.util.Map;

public class UserInfoProvider {

    public String getEmail(Map<String, String> userInfo) {
        return userInfo.get("email");
    }

    public String getFirstName(Map<String, String> userInfo) {
        return userInfo.get("given_name");
    }

    public String getLastName(Map<String, String> userInfo) {
        return userInfo.get("family_name");
    }

    public String getGender(Map<String, String> userInfo) {
        return userInfo.get("gender");
    }

    public String getBirthdate(Map<String, String> userInfo) {
        return userInfo.get("birthdate");
    }

    public String getLocale(Map<String, String> userInfo) {
        return userInfo.get("locale");
    }

    public String getSubject(Map<String, String> userInfo) {
        return userInfo.get("sub");
    }
}
