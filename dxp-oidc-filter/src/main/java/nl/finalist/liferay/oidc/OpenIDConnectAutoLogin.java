package nl.finalist.liferay.oidc;


import com.liferay.portal.configuration.metatype.bnd.util.ConfigurableUtil;
import com.liferay.portal.kernel.log.Log;
import com.liferay.portal.kernel.log.LogFactoryUtil;
import com.liferay.portal.kernel.module.configuration.ConfigurationProvider;
import com.liferay.portal.kernel.security.auto.login.AutoLogin;
import com.liferay.portal.kernel.security.auto.login.BaseAutoLogin;
import com.liferay.portal.kernel.service.UserLocalService;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import nl.finalist.liferay.oidc.configuration.OpenIDConnectOCDConfiguration;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Modified;
import org.osgi.service.component.annotations.Reference;

import java.util.Map;

/**
 * @see LibAutoLogin
 */
@Component(
    immediate = true,
    service = AutoLogin.class,
    configurationPid = "nl.finalist.liferay.oidc.OpenIDConnectOCDConfiguration"
)
public class OpenIDConnectAutoLogin extends BaseAutoLogin {

    private static final Log LOG = LogFactoryUtil.getLog(OpenIDConnectAutoLogin.class);

    @Reference
    private UserLocalService _userLocalService;

    private LibAutoLogin libAutologin;

    //private ConfigurationProvider _configurationProvider;

    /*@Reference
    protected void setConfigurationProvider(ConfigurationProvider configurationProvider) {
        _configurationProvider = configurationProvider;
    }*/

    public OpenIDConnectAutoLogin() {
        super();
    }

    /*@Activate
    protected void activate() {
        libAutologin = new LibAutoLogin(new Liferay70Adapter(_userLocalService, _configurationProvider));
    }*/

    @Activate
    @Modified
    protected void activate(Map<String, Object> properties) {
        OIDCConfiguration _configuration = ConfigurableUtil.createConfigurable(OpenIDConnectOCDConfiguration.class, properties);
        libAutologin = new LibAutoLogin(new Liferay70Adapter(_userLocalService, _configuration));
    }

    @Override
    protected String[] doLogin(HttpServletRequest request, HttpServletResponse response) throws Exception {
        return libAutologin.doLogin(request, response);
    }

}
