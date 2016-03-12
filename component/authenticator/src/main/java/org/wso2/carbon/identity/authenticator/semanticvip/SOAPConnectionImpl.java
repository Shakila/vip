/*
 *  Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

import org.apache.axiom.attachments.Attachments;
import org.apache.axiom.attachments.ConfigurableDataHandler;
import org.apache.axiom.om.OMAttribute;
import org.apache.axiom.om.OMElement;
import org.apache.axiom.om.OMNode;
import org.apache.axiom.om.OMText;
import org.apache.axiom.soap.SOAPEnvelope;
import org.apache.axiom.soap.SOAPHeaderBlock;
import org.apache.axis2.AxisFault;
import org.apache.axis2.addressing.EndpointReference;
import org.apache.axis2.client.OperationClient;
import org.apache.axis2.client.Options;
import org.apache.axis2.client.ServiceClient;
import org.apache.axis2.context.ConfigurationContext;
import org.apache.axis2.context.ConfigurationContextFactory;
import org.apache.axis2.context.MessageContext;
import org.apache.axis2.description.AxisService;
import org.apache.axis2.engine.AxisConfiguration;
import org.apache.axis2.engine.DispatchPhase;
import org.apache.axis2.engine.Phase;
import org.apache.axis2.saaj.MessageFactoryImpl;
import org.apache.axis2.saaj.util.IDGenerator;
import org.apache.axis2.saaj.util.SAAJUtil;
import org.apache.axis2.saaj.util.UnderstandAllHeadersHandler;

import javax.activation.DataHandler;
import javax.xml.namespace.QName;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;

import javax.xml.soap.AttachmentPart;
import javax.xml.soap.MimeHeader;
import javax.xml.soap.SOAPBody;
import javax.xml.soap.SOAPConnection;
import javax.xml.soap.SOAPElement;
import javax.xml.soap.SOAPException;
import javax.xml.soap.SOAPHeader;
import javax.xml.soap.SOAPHeaderElement;
import javax.xml.soap.SOAPMessage;
import javax.xml.soap.SOAPPart;

public class SOAPConnectionImpl extends SOAPConnection {
    private boolean closed = false;
    private final ConfigurationContext configurationContext;

    SOAPConnectionImpl() throws SOAPException {
        try {
            this.configurationContext = ConfigurationContextFactory.createConfigurationContextFromFileSystem((String) null, (String) null);
            this.disableMustUnderstandProcessing(this.configurationContext.getAxisConfiguration());
        } catch (AxisFault var2) {
            throw new SOAPException(var2);
        }
    }

    public SOAPMessage call(SOAPMessage request, Object endpoint) throws SOAPException {
        if (this.closed) {
            throw new SOAPException("SOAPConnection closed");
        } else {
            URL url;
            try {
                url = endpoint instanceof URL ? (URL) endpoint : new URL(endpoint.toString());
            } catch (MalformedURLException var29) {
                throw new SOAPException(var29.getMessage());
            }
            Options options = new Options();
            options.setTo(new EndpointReference(url.toString()));
            ServiceClient serviceClient;
            OperationClient opClient;
            try {
                serviceClient = new ServiceClient(this.configurationContext, (AxisService) null);
                opClient = serviceClient.createClient(ServiceClient.ANON_OUT_IN_OP);
            } catch (AxisFault var28) {
                throw new SOAPException(var28);
            }
            options.setProperty("CHARACTER_SET_ENCODING", request.getProperty("javax.xml.soap.character-set-encoding"));
            opClient.setOptions(options);
            MessageContext requestMsgCtx = new MessageContext();
            SOAPEnvelope envelope;
            Iterator responseMsgCtx;
            String attachments;
            if (isMTOM(request)) {
                envelope = SAAJUtil.toOMSOAPEnvelope(request);
                options.setProperty("enableMTOM", "true");
            } else {
                envelope = SAAJUtil.toOMSOAPEnvelope(request.getSOAPPart().getDocumentElement());
                if (request.countAttachments() != 0) {
                    Attachments httpHeaders = requestMsgCtx.getAttachmentMap();
                    Object arr$;
                    for (responseMsgCtx = request.getAttachments(); responseMsgCtx.hasNext(); httpHeaders.addDataHandler(attachments, (DataHandler) arr$)) {
                        AttachmentPart response = (AttachmentPart) responseMsgCtx.next();
                        attachments = response.getContentId();
                        if (attachments == null) {
                            attachments = IDGenerator.generateID();
                        }
                        arr$ = response.getDataHandler();
                        if (!SAAJUtil.compareContentTypes(response.getContentType(), ((DataHandler) arr$).getContentType())) {
                            ConfigurableDataHandler ex = new ConfigurableDataHandler(((DataHandler) arr$).getDataSource());
                            ex.setContentType(response.getContentType());
                            arr$ = ex;
                        }
                    }
                    options.setProperty("enableSwA", "true");
                }
            }
            HashMap var31 = null;
            responseMsgCtx = request.getMimeHeaders().getAllHeaders();
            while (responseMsgCtx.hasNext()) {
                MimeHeader var32 = (MimeHeader) responseMsgCtx.next();
                attachments = var32.getName().toLowerCase();
                if (attachments.equals("soapaction")) {
                    requestMsgCtx.setSoapAction(var32.getValue());
                } else if (!attachments.equals("content-type")) {
                    if (var31 == null) {
                        var31 = new HashMap();
                    }
                    var31.put(var32.getName(), var32.getValue());
                }
            }
            if (var31 != null) {
                requestMsgCtx.setProperty("HTTP_HEADERS", var31);
            }
            try {
                MessageContext var33;
                try {
                    requestMsgCtx.setEnvelope(envelope);
                    opClient.addMessageContext(requestMsgCtx);
                    opClient.execute(true);
                    var33 = opClient.getMessageContext("In");
                } catch (AxisFault var27) {
                    throw new SOAPException(var27.getMessage(), var27);
                }
                SOAPMessage var34 = this.getSOAPMessage(var33.getEnvelope());
                Attachments var36 = var33.getAttachmentMap();
                String[] var35 = var36.getAllContentIDs();
                int var37 = var35.length;
                for (int i$ = 0; i$ < var37; ++i$) {
                    String contentId = var35[i$];
                    if (!contentId.equals(var36.getSOAPPartContentID())) {
                        AttachmentPart ap = var34.createAttachmentPart(var36.getDataHandler(contentId));
                        ap.setContentId(contentId);
                        var34.addAttachmentPart(ap);
                    }
                }
                SOAPMessage var38 = var34;
                return var38;
            } finally {
                try {
                    serviceClient.cleanupTransport();
                    serviceClient.cleanup();
                } catch (AxisFault var26) {
                    throw new SOAPException(var26);
                }
            }
        }
    }

    private static boolean isMTOM(SOAPMessage soapMessage) {
        SOAPPart soapPart = soapMessage.getSOAPPart();
        String[] contentTypes = soapPart.getMimeHeader("Content-Type");
        return contentTypes != null && contentTypes.length > 0 ? SAAJUtil.normalizeContentType(contentTypes[0]).equals("application/xop+xml") : false;
    }

    private void disableMustUnderstandProcessing(AxisConfiguration config) {
        DispatchPhase phase = getDispatchPhase(config.getInFlowPhases());
        if (phase != null) {
            phase.addHandler(new UnderstandAllHeadersHandler());
        }
        phase = getDispatchPhase(config.getInFaultFlowPhases());
        if (phase != null) {
            phase.addHandler(new UnderstandAllHeadersHandler());
        }
    }

    private static DispatchPhase getDispatchPhase(List<Phase> phases) {
        Iterator i$ = phases.iterator();
        Phase phase;
        do {
            if (!i$.hasNext()) {
                return null;
            }
            phase = (Phase) i$.next();
        } while (!(phase instanceof DispatchPhase));
        return (DispatchPhase) phase;
    }

    public void close() throws SOAPException {
        if (this.closed) {
            throw new SOAPException("SOAPConnection Closed");
        } else {
            try {
                this.configurationContext.terminate();
            } catch (AxisFault var2) {
                throw new SOAPException(var2.getMessage());
            }
            this.closed = true;
        }
    }

    private SOAPMessage getSOAPMessage(SOAPEnvelope respOMSoapEnv) throws SOAPException {
        SOAPMessage response = new MessageFactoryImpl().createMessage();
        SOAPPart sPart = response.getSOAPPart();
        javax.xml.soap.SOAPEnvelope env = sPart.getEnvelope();
        SOAPBody body = env.getBody();
        SOAPHeader header = env.getHeader();
        org.apache.axiom.soap.SOAPHeader header2 = respOMSoapEnv.getHeader();
        if (header2 != null) {
            Iterator hbIter = header2.examineAllHeaderBlocks();
            while (hbIter.hasNext()) {
                SOAPHeaderBlock hb = (SOAPHeaderBlock) hbIter.next();
                QName hbQName = hb.getQName();
                SOAPHeaderElement headerEle = header.addHeaderElement(env.createName(hbQName.getLocalPart(), hbQName.getPrefix(), hbQName.getNamespaceURI()));
                Iterator role = hb.getAllAttributes();
                while (role.hasNext()) {
                    OMAttribute attr = (OMAttribute) role.next();
                    QName attrQName = attr.getQName();
                    headerEle.addAttribute(env.createName(attrQName.getLocalPart(), attrQName.getPrefix(), attrQName.getNamespaceURI()), attr.getAttributeValue());
                }
                String role1 = hb.getRole();
                if (role1 != null) {
                    headerEle.setActor(role1);
                }
                headerEle.setMustUnderstand(hb.getMustUnderstand());
                this.toSAAJElement(headerEle, hb, response);
            }
        }
        this.toSAAJElement(body, respOMSoapEnv.getBody(), response);
        return response;
    }

    private void toSAAJElement(SOAPElement saajEle, OMNode omNode, SOAPMessage saajSOAPMsg) throws SOAPException {
        if (!(omNode instanceof OMText)) {
            if (omNode instanceof OMElement) {
                OMElement omEle = (OMElement) omNode;
                OMNode omChildNode;
                SOAPElement saajChildEle;
                for (Iterator childIter = omEle.getChildren(); childIter.hasNext(); this.toSAAJElement(saajChildEle, omChildNode, saajSOAPMsg)) {
                    omChildNode = (OMNode) childIter.next();
                    saajChildEle = null;
                    if (omChildNode instanceof OMText) {
                        OMText omChildEle1 = (OMText) omChildNode;
                        if (omChildEle1.isOptimized()) {
                            DataHandler omChildQName1 = (DataHandler) omChildEle1.getDataHandler();
                            AttachmentPart attribIter1 = saajSOAPMsg.createAttachmentPart(omChildQName1);
                            String attr1 = IDGenerator.generateID();
                            attribIter1.setContentId("<" + attr1 + ">");
                            attribIter1.setContentType(omChildQName1.getContentType());
                            saajSOAPMsg.addAttachmentPart(attribIter1);
                            SOAPElement attrQName1 = saajEle.addChildElement("Include", "xop", "http://www.w3.org/2004/08/xop/include");
                            attrQName1.addAttribute(saajSOAPMsg.getSOAPPart().getEnvelope().createName("href"), "cid:" + attr1);
                        } else {
                            saajChildEle = saajEle.addTextNode(omChildEle1.getText());
                        }
                    } else if (omChildNode instanceof OMElement) {
                        OMElement omChildEle = (OMElement) omChildNode;
                        QName omChildQName = omChildEle.getQName();
                        saajChildEle = saajEle.addChildElement(omChildQName.getLocalPart(), omChildQName.getPrefix(), omChildQName.getNamespaceURI());
                        Iterator attribIter = omChildEle.getAllAttributes();
                        while (attribIter.hasNext()) {
                            OMAttribute attr = (OMAttribute) attribIter.next();
                            QName attrQName = attr.getQName();
                            saajChildEle.addAttribute(saajSOAPMsg.getSOAPPart().getEnvelope().createName(attrQName.getLocalPart(), attrQName.getPrefix(), attrQName.getNamespaceURI()), attr.getAttributeValue());
                        }
                    }
                }
            }
        }
    }
}
