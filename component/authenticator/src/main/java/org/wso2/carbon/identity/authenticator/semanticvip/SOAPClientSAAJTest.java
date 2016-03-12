package org.wso2.carbon.identity.authenticator.semanticvip;/*
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

import javax.xml.soap.MessageFactory;
import javax.xml.soap.SOAPConnection;
import javax.xml.soap.SOAPConnectionFactory;
import javax.xml.soap.SOAPMessage;
import javax.xml.soap.SOAPBody;
import javax.xml.soap.SOAPElement;
import javax.xml.soap.SOAPEnvelope;
import javax.xml.soap.SOAPPart;
import javax.xml.soap.MimeHeaders;
import javax.xml.soap.Name;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.InputStream;
import java.io.IOException;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.KeyStoreException;
import java.security.KeyManagementException;
import java.security.UnrecoverableKeyException;
import java.security.KeyStore;

public class SOAPClientSAAJTest {

    public static void sendCall(String certPath, String password) {
        try {
            setHttpsClientCert(certPath, password);
            System.setProperty("javax.xml.soap.SOAPConnectionFactory", "org.apache.axis2.saaj.SOAPConnectionFactoryImpl");

            // Create SOAP Connection
            SOAPConnectionFactory soapConnectionFactory = SOAPConnectionFactory.newInstance();
            SOAPConnection soapConnection = soapConnectionFactory.createConnection();

            // Send SOAP Message to SOAP Server
            String url = "https://vipservices-auth.verisign.com/val/soap";
            String serverURI = "http://www.verisign.com/2006/08/vipservice";

            SOAPMessage soapResponse = soapConnection.call(createSOAPRequest(serverURI), url);

            soapConnection.close();
        } catch (Exception e) {
            System.err.println("Error occurred while sending SOAP Request to Server");
            e.printStackTrace();
        }
    }

    private static SOAPMessage createSOAPRequest(String serverURI) throws Exception {
        MessageFactory messageFactory = MessageFactory.newInstance();
        SOAPMessage soapMessage = messageFactory.createMessage();
        SOAPPart soapPart = soapMessage.getSOAPPart();

        // SOAP Envelope
        SOAPEnvelope envelope = soapPart.getEnvelope();
        envelope.addNamespaceDeclaration("con", serverURI); 
//         envelope.addNamespaceDeclaration("soapenv", "http://schemas.xmlsoap.org/soap/envelope/");        
        SOAPBody soapBody = envelope.getBody();
        SOAPElement soapBodyElem = soapBody.addChildElement("Validate", "con");
Name attributeName = envelope.createName("Version");
soapBodyElem.addAttribute(attributeName, "2.0");
        SOAPElement soapBodyElem1 = soapBodyElem.addChildElement("TokenId", "con");
        soapBodyElem1.addTextNode("VSST68749973");
        SOAPElement soapBodyElem2 = soapBodyElem.addChildElement("OTP", "con");
        soapBodyElem2.addTextNode("460228");

        MimeHeaders headers = soapMessage.getMimeHeaders();
        headers.addHeader("SOAPAction", serverURI );

        soapMessage.saveChanges();

        /* Print the request message */
        System.out.print("Request SOAP Message = ");
        soapMessage.writeTo(System.out);
        System.out.println();

        return soapMessage;
    }

    
     public static void setHttpsClientCert(String certificateFile, String certPassword) {
        try {
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
        } catch (KeyStoreException e) {
        } catch (NoSuchAlgorithmException e) {
        } catch (FileNotFoundException e) {
        } catch (IOException e) {
        } catch (CertificateException e) {
        } catch (UnrecoverableKeyException e) {
        } catch (KeyManagementException e) {
        }
    }
}