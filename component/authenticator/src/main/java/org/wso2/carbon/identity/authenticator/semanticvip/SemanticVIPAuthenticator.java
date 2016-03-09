/*
 *  Copyright (c) 2015, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *  WSO2 Inc. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 *
 */

package org.wso2.carbon.identity.authenticator.semanticvip;

import org.apache.commons.lang.StringUtils;
import org.wso2.carbon.identity.application.authentication.framework.LocalApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.config.ConfigurationFacade;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.exception.InvalidCredentialsException;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.authenticator.oidc.OpenIDConnectAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.FederatedApplicationAuthenticator;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.user.core.UserRealm;
import org.wso2.carbon.user.core.UserStoreException;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Properties;

/**
 * Authenticator of SemanticVIP
 */
public class SemanticVIPAuthenticator extends OpenIDConnectAuthenticator implements FederatedApplicationAuthenticator {

    private static Log log = LogFactory.getLog(SemanticVIPAuthenticator.class);

    /**
     * Check whether the authentication or logout request can be handled by the authenticator
     */
    public boolean canHandle(HttpServletRequest request) {
        if (log.isDebugEnabled()) {
            log.debug("Inside SemanticVIPAuthenticator canHandle method");
        }
        return (StringUtils.isNotEmpty(request.getParameter(SemanticVIPAuthenticatorConstants.SECURITY_CODE)));
    }

    /**
     * Initiate the authentication request
     */
    @Override
    protected void initiateAuthenticationRequest(HttpServletRequest request,
                                                 HttpServletResponse response, AuthenticationContext context)
            throws AuthenticationFailedException {
        try {
            Map<String, String> authenticatorProperties = context.getAuthenticatorProperties();
            String p12file = authenticatorProperties.get(SemanticVIPAuthenticatorConstants.VIP_P12FILE);
            String p12password = authenticatorProperties.get(SemanticVIPAuthenticatorConstants.VIP_P12PASSWORD);
            if (StringUtils.isNotEmpty(p12file) && StringUtils.isNotEmpty(p12password)) {
                Properties vipProperties = new Properties();
                String resourceName = SemanticVIPAuthenticatorConstants.PROPERTIES_FILE;
                ClassLoader loader = Thread.currentThread().getContextClassLoader();
                InputStream resourceStream = loader.getResourceAsStream(resourceName);
                try {
                    vipProperties.load(resourceStream);
                } catch (IOException e) {
                    log.error("Unable to load the properties file", e);
                    throw new AuthenticationFailedException("Unable to load the properties file", e);
                }
                String retryParam = "";
                if (context.isRetrying()) {
                    retryParam = SemanticVIPAuthenticatorConstants.RETRY_PARAMS;
                }
                String vipPage = ConfigurationFacade.getInstance().getAuthenticationEndpointURL()
                        .replace(SemanticVIPAuthenticatorConstants.LOGIN_PAGE, SemanticVIPAuthenticatorConstants.VIP_PAGE);
                String queryParams = FrameworkUtils
                        .getQueryStringWithFrameworkContextId(context.getQueryParams(),
                                context.getCallerSessionKey(),
                                context.getContextIdentifier());
                response.sendRedirect(response.encodeRedirectURL(vipPage + ("?" + queryParams))
                        + SemanticVIPAuthenticatorConstants.AUTHENTICATORS + getName() + ":"
                        + SemanticVIPAuthenticatorConstants.LOCAL
                        + retryParam);
            } else {
                log.error("Certificate path and password cannot be null");
                throw new AuthenticationFailedException("Certificate path and password cannot be null");
            }
        } catch (IOException e) {
            throw new AuthenticationFailedException("Exception while redirecting the page: " + e.getMessage(), e);
        }
    }

    /**
     * Process the response of the Semantic VIP
     */
    @Override
    protected void processAuthenticationResponse(HttpServletRequest request, HttpServletResponse response,
                                                 AuthenticationContext context) throws AuthenticationFailedException {
        try {
            if (StringUtils.isEmpty(request.getParameter(SemanticVIPAuthenticatorConstants.SECURITY_CODE))) {
                log.error("Security Code cannot not be null");
                throw new InvalidCredentialsException("Security Code cannot not be null");
            }
            Map<String, String> authenticatorProperties = context.getAuthenticatorProperties();
            String tokenId;
            String username = null;
            for (Integer stepMap : context.getSequenceConfig().getStepMap().keySet()) {
                if (context.getSequenceConfig().getStepMap().get(stepMap).getAuthenticatedUser() != null &&
                        context.getSequenceConfig().getStepMap().get(stepMap).getAuthenticatedAutenticator()
                                .getApplicationAuthenticator() instanceof LocalApplicationAuthenticator) {
                    username =
                            String.valueOf(context.getSequenceConfig().getStepMap().get(stepMap).getAuthenticatedUser());
                    break;
                }
            }
            if (StringUtils.isNotEmpty(username)) {
                UserRealm userRealm;
                String tenantDomain = MultitenantUtils.getTenantDomain(username);
                int tenantId = IdentityTenantUtil.getTenantId(tenantDomain);
                RealmService realmService = IdentityTenantUtil.getRealmService();
                try {
                    userRealm = (UserRealm) realmService.getTenantUserRealm(tenantId);
                } catch (org.wso2.carbon.user.api.UserStoreException e) {
                    throw new AuthenticationFailedException("Cannot find the user realm", e);
                }
                username = MultitenantUtils.getTenantAwareUsername(String.valueOf(username));
                if (userRealm != null) {
                    tokenId = userRealm.getUserStoreManager()
                            .getUserClaimValue(username, SemanticVIPAuthenticatorConstants.VIP_CREDENTIAL_ID_CLAIM, null).toString();
                    if (StringUtils.isEmpty(tokenId)) {
                        log.error("The Credential ID can not be null.");
                        throw new AuthenticationFailedException("The Credential ID can not be null.");
                    } else {
                        String p12file = authenticatorProperties.get(SemanticVIPAuthenticatorConstants.VIP_P12FILE);
                        String p12password = authenticatorProperties.get(SemanticVIPAuthenticatorConstants.VIP_P12PASSWORD);
                        VIPManager.setHttpsClientCert(p12file, p12password);

                        String secretCode = request.getParameter(SemanticVIPAuthenticatorConstants.SECURITY_CODE);
                        VIPManager.invokeSOAP(tokenId, secretCode);
                    }
                }
            }
        } catch (AuthenticationFailedException e) {
            log.error(e);
            throw new AuthenticationFailedException(e.getMessage());
        } catch (UserStoreException e) {
            log.error("Cannot find the user claim for VIP Credential ID", e);
            throw new AuthenticationFailedException("Cannot find the user claim for VIP Credential ID " + e.getMessage(), e);
        } catch (Exception e) {
            log.error("Error while adding certificate", e);
            throw new AuthenticationFailedException("Error while adding certificate", e);
        }
    }

    /**
     * Get the friendly name of the Authenticator
     */
    @Override
    public String getFriendlyName() {
        return SemanticVIPAuthenticatorConstants.AUTHENTICATOR_FRIENDLY_NAME;
    }

    /**
     * Get the name of the Authenticator
     */
    @Override
    public String getName() {
        return SemanticVIPAuthenticatorConstants.AUTHENTICATOR_NAME;
    }

    /**
     * Get Configuration Properties
     */
    @Override
    public List<Property> getConfigurationProperties() {

        List<Property> configProperties = new ArrayList<Property>();
        Property p12file = new Property();
        p12file.setName(SemanticVIPAuthenticatorConstants.VIP_P12FILE);
        p12file.setDisplayName("P12FILE");
        p12file.setRequired(true);
        p12file.setDescription("Enter your p12_file path");
        p12file.setDisplayOrder(0);
        configProperties.add(p12file);

        Property p12password = new Property();
        p12password.setName(SemanticVIPAuthenticatorConstants.VIP_P12PASSWORD);
        p12password.setDisplayName("P12Password");
        p12password.setConfidential(true);
        p12password.setRequired(true);
        p12password.setDescription("Enter your p12_password");
        p12password.setDisplayOrder(1);
        configProperties.add(p12password);

        return configProperties;
    }
}

