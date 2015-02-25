/**
 * See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * con terra GmbH licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */


package de.conterra.suite.security.portal.gpx;

import com.esri.gpt.catalog.schema.NamespaceContextImpl;
import com.esri.gpt.catalog.schema.Namespaces;
import com.esri.gpt.framework.collection.StringAttributeMap;
import com.esri.gpt.framework.security.codec.PC1_Encryptor;
import com.esri.gpt.framework.security.identity.NotAuthorizedException;
import com.esri.gpt.framework.security.principal.RoleSet;
import com.esri.gpt.framework.security.principal.User;
import com.esri.gpt.framework.security.principal.UserAttribute;
import com.esri.gpt.framework.util.ResourcePath;
import com.esri.gpt.framework.util.Val;
import com.esri.gpt.sdisuite.IntegrationContext;
import com.esri.gpt.sdisuite.IntegrationResponse;
import org.apache.commons.codec.binary.Base64;
import org.opensaml.SAMLAssertion;
import org.opensaml.SAMLAttribute;
import org.opensaml.SAMLAttributeStatement;
import org.opensaml.SAMLAuthenticationStatement;
import org.opensaml.SAMLException;
import org.opensaml.SAMLNameIdentifier;
import org.opensaml.SAMLResponse;
import org.opensaml.SAMLStatement;
import org.opensaml.SAMLSubject;
import org.w3c.dom.Document;

import javax.xml.namespace.QName;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathFactory;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.security.Key;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.text.MessageFormat;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.Iterator;
import java.util.logging.Logger;

public class EmbeddedSAMLTokenIntegrationContext extends IntegrationContext {


    /**
     * The Logger.
     */
    private static Logger LOGGER = Logger.getLogger(EmbeddedSAMLTokenIntegrationContext.class.getName());

    private static final String USER_ATTR_SECURITY_TOKEN = "saml1.security.token";
    private static final String USER_ATTR_SECURITY_TOKEN_CREATIONDATE = "saml1.security.token.createdAt";

    private static final String CONFIG_PARAM_KEYSTORE_TYPE = "sdisuite.keystore.type";
    private static final String CONFIG_PARAM_KEYSTORE_LOC = "sdisuite.keystore.location";
    private static final String CONFIG_PARAM_KEYSTORE_PW = "sdisuite.keystore.passwd";
    private static final String CONFIG_PARAM_KEYSTORE_KEY_ALIAS = "sdisuite.keystore.key.alias";
    private static final String CONFIG_PARAM_KEYSTORE_KEY_PW = "sdisuite.keystore.key.passwd";
    private static final String CONFIG_PARAM_KEYSTORE_PWS_ENCRYPTED = "sdisuite.keystore.passwds.encrypted";
    private static final String CONFIG_PARAM_ROLE_ATTRIBUTE_NAME = "sdisuite.role.attributename";
    private static final String CONFIG_PARAM_ROLE_ATTRIBUTE_NAMESPACE = "sdisuite.role.attributenamespace";
    private static final String CONFIG_PARAM_TOKEN_TIMEOUT = "sdisuite.token.timeout";
    private static final String CONFIG_PARAM_TOKEN_ISSUER = "sdisuite.token.issuer";
    private static final String CONFIG_PARAM_TOKEN_SIGN_SAMLRESPONSE = "sdisuite.token.sign.samlresponse";


    /**
     * holds the public key (certificate) embedded in the token
     */
    private Certificate m_applicationCertificate;
    /**
     * holds the private key used to sign the token.
     */
    private Key m_applicationPrivateKey;
    /**
     * holds the name of the role attribute in saml tickets.
     */
    private String m_roleAttributeName;
    /**
     * holds the attribute namespace of role attributes.
     */
    private String m_roleAttributeNamespace;
    /**
     * holds the token timeout in seconds.
     */
    private int m_tokenTimout;
    /**
     * holds the token issuer name.
     */
    private String m_tokenIssuer;
    /**
     * flag if the saml response element shall be signed, too
     */
    private boolean m_tokenSignSAMLResponse;

    @Override
    public void setConfig(StringAttributeMap config) {
        super.setConfig(config);
        LOGGER.entering("EmbeddedSAMLTokenIntegrationContext", "setConfig");
        initKeyStore(getConfig());
        m_roleAttributeName = getValFromConfig(CONFIG_PARAM_ROLE_ATTRIBUTE_NAME,
                "urn:conterra:names:sdi-suite:policy:attribute:role");
        m_roleAttributeNamespace = getValFromConfig(CONFIG_PARAM_ROLE_ATTRIBUTE_NAMESPACE, "urn:ct:names");
        m_tokenTimout = Integer.parseInt(getValFromConfig(CONFIG_PARAM_TOKEN_TIMEOUT, "600"));
        m_tokenIssuer = getValFromConfig(CONFIG_PARAM_TOKEN_ISSUER, "gpt");
        m_tokenSignSAMLResponse = "true"
                .equalsIgnoreCase(getValFromConfig(CONFIG_PARAM_TOKEN_SIGN_SAMLRESPONSE, "false"));
    }

    private void initKeyStore(StringAttributeMap stringAttributeMap) {
        LOGGER.entering("EmbeddedSAMLTokenIntegrationContext", "initKeyStore");
        String type = getValFromConfig(CONFIG_PARAM_KEYSTORE_TYPE, "JKS");
        String keystoreLoc = getValFromConfig(CONFIG_PARAM_KEYSTORE_LOC, "/gpt/config/keystore.jks");
        String keystorePw = getValFromConfig(CONFIG_PARAM_KEYSTORE_PW, "changeit");
        String keyAlias = getValFromConfig(CONFIG_PARAM_KEYSTORE_KEY_ALIAS, "gpt-security");
        String keyPw = getValFromConfig(CONFIG_PARAM_KEYSTORE_KEY_PW, "changeit");

        LOGGER.finest(MessageFormat.format("Instantiating keystore from: {0}", keystoreLoc));
        LOGGER.finest(MessageFormat.format("Using certificate alias: {0}", keyAlias));
        if ("true".equalsIgnoreCase(getValFromConfig(CONFIG_PARAM_KEYSTORE_PWS_ENCRYPTED, "false"))) {
            // TODO: test this stuff
            keystorePw = PC1_Encryptor.decrypt(keystorePw);
            keyPw = PC1_Encryptor.decrypt(keyPw);
        }

        try {
            KeyStore keystore = KeyStore.getInstance(type);
            InputStream in = findInputStream(keystoreLoc);
            try {
                keystore.load(in, keystorePw.toCharArray());
                Certificate cert = keystore.getCertificate(keyAlias);
                Key key = keystore.getKey(keyAlias, keyPw.toCharArray());
                m_applicationCertificate = cert;
                m_applicationPrivateKey = key;
                if (cert == null || key == null) {
                    throw new IllegalArgumentException("key alias '" + keyAlias + "> not found!");
                }
            } finally {
                try {
                    in.close();
                } catch (IOException e) {
                    // ignore
                }
            }
        } catch (Exception e) {
            throw new IllegalStateException("Can't load certificate and key with alias '" + keyAlias
                    + "' from keystore '" + keystoreLoc + "'! Msg" + e, e);
        }
    }

    /**
     * Uses {@link ResourcePath} class to resolve the keystore location.
     *
     * @throws IOException
     */
    private InputStream findInputStream(String location) throws IOException {
        LOGGER.entering("EmbeddedSAMLTokenIntegrationContext", "findInputStream");
        // _externalFolder = "file:///C:/Program%20Files/ESRI/GPT9/gpt/";
        // _localFolder = "gpt/";
        return new ResourcePath().makeUrl(location).openStream();
    }

    private String getValFromConfig(String key, String defaultVal) {
        StringAttributeMap conf = getConfig();
        String val = conf.getValue(key);
        return Val.chkStr(val, defaultVal);
    }

    protected boolean isToken(final User user) {
        LOGGER.entering("EmbeddedSAMLTokenIntegrationContext", "isToken");
        return user.getProfile().containsKey(USER_ATTR_SECURITY_TOKEN);
    }

    protected String getToken(final User user) {
        LOGGER.entering("EmbeddedSAMLTokenIntegrationContext", "getToken");
        UserAttribute attr = user.getProfile().get(USER_ATTR_SECURITY_TOKEN);
        return attr != null ? attr.getValue() : null;
    }

    protected long getTokenCreationTime(final User user) {
        LOGGER.entering("EmbeddedSAMLTokenIntegrationContext", "getTokenCreationTime");
        UserAttribute attr = user.getProfile().get(USER_ATTR_SECURITY_TOKEN_CREATIONDATE);
        return attr != null ? Long.parseLong(attr.getValue()) : -1;
    }

    private String createToken(User user) throws Exception {
        LOGGER.entering("EmbeddedSAMLTokenIntegrationContext", "createToken");
        // non authenticated users -> exception
        user.getAuthenticationStatus().assertLoggedIn();

        String username = user.getProfile().getUsername();
        RoleSet roles = user.getAuthenticationStatus().getAuthenticatedRoles();

        // we create a ticket with the users id and including the user roles

        Calendar now = Calendar.getInstance();
        Calendar timeout = (Calendar) now.clone();
        timeout.add(Calendar.SECOND, m_tokenTimout);

        SAMLNameIdentifier identifier =
                new SAMLNameIdentifier(username, null, "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified");

        SAMLSubject samlSubject = new SAMLSubject(identifier, null, null, null);
        Collection<SAMLStatement> statements = new ArrayList<SAMLStatement>();
        SAMLAuthenticationStatement authnStatement = new SAMLAuthenticationStatement((SAMLSubject) samlSubject.clone(),
                "urn:oasis:names:tc:SAML:1.0:am:password", now.getTime(),
                null, null, null);
        statements.add(authnStatement);

        Collection<SAMLAttribute> samlAttributes = new ArrayList<SAMLAttribute>();
        if (!roles.isEmpty()) {
            // for (String role : roles) {
            SAMLAttribute roleAttribute =
                    new SAMLAttribute(m_roleAttributeName, m_roleAttributeNamespace, new QName(
                            org.opensaml.XML.XSD_NS, "string"), 0,
                            roles);
            samlAttributes.add(roleAttribute);
            // }
        }
        if (!samlAttributes.isEmpty()) {
            SAMLAttributeStatement attributeStatement =
                    new SAMLAttributeStatement((SAMLSubject) samlSubject.clone(), samlAttributes);
            statements.add(attributeStatement);
        }

        // allow 5 seconds clock difference
        Date notBefore = new Date(now.getTime().getTime() - 5000);
        Date notOnOrAfter = new Date(timeout.getTime().getTime() + 5000);

        SAMLAssertion assertion = new SAMLAssertion(m_tokenIssuer, notBefore, notOnOrAfter, null, null, statements);

        SAMLResponse response = new SAMLResponse(null, null, Collections.singleton(assertion), null);
        // ensure canonicalization
        response.toString();

        Collection<Certificate> certificates = Collections.singleton(m_applicationCertificate);
        assertion.sign("http://www.w3.org/2000/09/xmldsig#rsa-sha1", m_applicationPrivateKey, certificates);
        if (m_tokenSignSAMLResponse) {
            response.sign("http://www.w3.org/2000/09/xmldsig#rsa-sha1", m_applicationPrivateKey, certificates);
        }
        return response.toString();
    }

    @Override
    public IntegrationResponse checkUrl(String url, User user, String username, String password, String licenseReturnUrl)
            throws NotAuthorizedException, Exception {
        LOGGER.entering("EmbeddedSAMLTokenIntegrationContext", "checkUrl");
        IntegrationResponse r = new IntegrationResponse();
        r.setSecured(false);
        r.setUrl(url);
        return r;
    }

    @Override
    public void ensureToken(User user) throws Exception {
        LOGGER.entering("EmbeddedSAMLTokenIntegrationContext", "ensureToken");
        if (!isToken(user) || isTokenTimeout(user)) {
            String creationDate = String.valueOf(System.currentTimeMillis());
            String token = createToken(user);
            user.getProfile().add(new UserAttribute(USER_ATTR_SECURITY_TOKEN, token));
            user.getProfile().add(new UserAttribute(USER_ATTR_SECURITY_TOKEN_CREATIONDATE, creationDate));
        }
    }

    private boolean isTokenTimeout(User user) {
        long createdAt = getTokenCreationTime(user);
        long now = System.currentTimeMillis();
        long lifetime = now - createdAt;
        // check if timeout is exceeded
        return (lifetime > Math.max(5, m_tokenTimout - 15) * 1000);
    }

    @Override
    public String getBase64EncodedToken(User user) throws Exception {
        LOGGER.entering("EmbeddedSAMLTokenIntegrationContext", "getBase64EncodedToken");
        ensureToken(user);
        return new String(Base64.encodeBase64(getToken(user).getBytes("UTF-8"), false), "UTF-8");
    }

    @Override
    public String getUsernameFromSAMLToken(String base64EncodedToken) throws Exception {
        LOGGER.entering("EmbeddedSAMLTokenIntegrationContext", "getUsernameFromSAMLToken");
        XPath xpath = XPathFactory.newInstance().newXPath();
        Namespaces ns = new Namespaces();
        ns.add("sa", org.opensaml.XML.SAML_NS);
        // ns.add("sp", org.opensaml.XML.SAMLP_NS);
        xpath.setNamespaceContext(new NamespaceContextImpl(ns));
        String userId = (String) xpath.evaluate(
                "//sa:Assertion/sa:AuthenticationStatement/sa:Subject/sa:NameIdentifier/text()",
                createAndVerifySamlResponse(base64EncodedToken),
                XPathConstants.STRING);
        String s = Val.chkStr(userId);
        LOGGER.finest(MessageFormat.format("Returning userid '{0}' from given token.", s));
        return s;
    }

    private Document createAndVerifySamlResponse(String base64EncodedToken) {
        LOGGER.entering("EmbeddedSAMLTokenIntegrationContext", "createAndVerifySamlResponse", base64EncodedToken);
        try {
            SAMLResponse samlResponse = new SAMLResponse(new ByteArrayInputStream(Base64.decodeBase64(base64EncodedToken.getBytes("UTF-8"))));
            Iterator lIterator = samlResponse.getAssertions();
            if (lIterator.hasNext()) {
                SAMLAssertion asserts = (SAMLAssertion) lIterator.next();
                asserts.verify(m_applicationCertificate);
            }
            return samlResponse.toDOM(true).getOwnerDocument();
        } catch (SAMLException e) {
            LOGGER.severe(MessageFormat.format("Caught SAML Exception during saml response creation: {0}. Returning null.", e.getMessage()));
            return null;
        } catch (UnsupportedEncodingException e) {
            LOGGER.severe(MessageFormat.format("Caught UnsupportedEncodingException during saml response creation: {0}. Returning null.", e.getMessage()));
            return null;
        }
    }

    @Override
    public void initializeUser(User user) throws Exception {
        LOGGER.entering("EmbeddedSAMLTokenIntegrationContext", "initializeUser");
        // not needed
    }

    @Override
    public void shutdown() throws Exception {
        LOGGER.entering("EmbeddedSAMLTokenIntegrationContext", "shutdown");
        // not needed
    }

}
