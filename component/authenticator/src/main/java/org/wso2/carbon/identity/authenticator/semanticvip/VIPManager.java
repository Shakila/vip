/*
 * Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *   WSO2 Inc. licenses this file to you under the Apache License,
 *   Version 2.0 (the "License"); you may not use this file except
 *   in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 */

package org.wso2.carbon.identity.authenticator.semanticvip;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;

import javax.xml.soap.MimeHeaders;
import javax.xml.soap.SOAPConnection;
import javax.xml.soap.SOAPConnectionFactory;
import javax.xml.soap.Name;
import javax.xml.soap.SOAPBody;
import javax.xml.soap.SOAPElement;
import javax.xml.soap.SOAPEnvelope;
import javax.xml.soap.MessageFactory;
import javax.xml.soap.SOAPMessage;
import javax.xml.soap.SOAPPart;
import javax.xml.soap.SOAPException;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;

import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.SecureRandom;
import java.security.KeyStoreException;
import java.security.UnrecoverableKeyException;

import java.util.Properties;

public class VIPManager {
    private static final Log log = LogFactory.getLog(VIPManager.class);

    /**
     * Set the client certificate to Default SSL Context
     *
     * @param certificateFile File containing certificate (PKCS12 format)
     * @param certPassword    Password of certificate
     * @throws Exception
     */
    public static void setHttpsClientCert(String certificateFile, String certPassword) throws KeyStoreException,
            NoSuchAlgorithmException, IOException, CertificateException, UnrecoverableKeyException,
            KeyManagementException {
        if (certificateFile == null || !new File(certificateFile).exists()) {
            return;
        }
        KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance("SunX509");
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        InputStream keyInput = new FileInputStream(certificateFile);
        keyStore.load(keyInput, certPassword.toCharArray());
        keyInput.close();
        keyManagerFactory.init(keyStore, certPassword.toCharArray());
        SSLContext context = SSLContext.getInstance("TLS");
        context.init(keyManagerFactory.getKeyManagers(), null, new SecureRandom());
        SSLContext.setDefault(context);
    }

    /**
     * Method to create SOAP connection
     */
    public static void invokeSOAP(String tokenId, String securityCode) throws AuthenticationFailedException {
        SOAPConnectionFactory soapConnectionFactory = null;
        SOAPConnection soapConnection = null;
        try {
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

            SOAPMessage soapMessage = null;
            soapConnectionFactory = SOAPConnectionFactory.newInstance();
            soapConnection = soapConnectionFactory.createConnection();
            String url = vipProperties.getProperty(SemanticVIPAuthenticatorConstants.VIP_URL);
            soapMessage = validationSOAPMessage(vipProperties, tokenId, securityCode);

            String reasonCode = null;
            SOAPMessage soapResponse = soapConnection.call(soapMessage, url);
            if (soapResponse.getSOAPBody().getElementsByTagName("ValidateResponse").getLength() != 0) {
                reasonCode =
                        soapResponse.getSOAPBody().getElementsByTagName("ReasonCode").item(0).getTextContent().toString();
                if (!SemanticVIPAuthenticatorConstants.SUCCESS_CODE.equals(reasonCode)) {
                    String error = soapResponse.getSOAPBody().getElementsByTagName("StatusMessage").item(0)
                            .getTextContent().toString();
                    throw new AuthenticationFailedException("Error occurred while validating the credentials:" + error);
                }
            } else {
                throw new AuthenticationFailedException("Unable to find the provisioning ID");
            }

        } catch (SOAPException e) {
            throw new AuthenticationFailedException("Error occurred while sending SOAP Request to Server", e);
        } finally {
            try {
                if (soapConnection != null) {
                    soapConnection.close();
                }
            } catch (SOAPException e) {
                log.error("Error while closing the SOAP connection", e);
            }
        }
    }

    private static SOAPMessage validationSOAPMessage(Properties vipProperties, String tokenId, String securityCode)
            throws SOAPException {
        MessageFactory messageFactory = MessageFactory.newInstance();
        SOAPMessage soapMessage = messageFactory.createMessage();
        SOAPPart soapPart = soapMessage.getSOAPPart();
        String serverURI = vipProperties.getProperty(SemanticVIPAuthenticatorConstants.SOAP_VIP_NS_URI);
        SOAPEnvelope envelope = soapPart.getEnvelope();
        String namespacePrefix = SemanticVIPAuthenticatorConstants.SOAP_NAMESPACE_PREFIX;
        envelope.addNamespaceDeclaration(SemanticVIPAuthenticatorConstants.SOAP_ENVELOP_NAMESPACE_PREFIX,
                SemanticVIPAuthenticatorConstants.SOAP_ENVELOP_HEADER);
        envelope.addNamespaceDeclaration(namespacePrefix, serverURI);
        SOAPBody soapBody = envelope.getBody();
        SOAPElement soapBodyElem =
                soapBody.addChildElement(SemanticVIPAuthenticatorConstants.SOAP_ACTION_VALIDATE, namespacePrefix);
        Name attributeName = envelope.createName(SemanticVIPAuthenticatorConstants.VERSION);
        soapBodyElem.addAttribute(attributeName, vipProperties.getProperty(SemanticVIPAuthenticatorConstants.VERSION));
        SOAPElement soapBodyElem1 =
                soapBodyElem.addChildElement(SemanticVIPAuthenticatorConstants.TOKEN_ID, namespacePrefix);
        soapBodyElem1.addTextNode(tokenId);
        SOAPElement soapBodyElem2 =
                soapBodyElem.addChildElement(SemanticVIPAuthenticatorConstants.OTP, namespacePrefix);
        soapBodyElem2.addTextNode(securityCode);
        MimeHeaders headers = soapMessage.getMimeHeaders();
        headers.addHeader(SemanticVIPAuthenticatorConstants.SOAP_ACTION, serverURI);
        soapMessage.saveChanges();
        return soapMessage;
    }
}
