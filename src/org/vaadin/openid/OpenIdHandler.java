package org.vaadin.openid;

import java.io.IOException;
import java.io.OutputStream;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.EnumMap;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Map.Entry;
import java.util.concurrent.atomic.AtomicInteger;

import javax.servlet.http.HttpServletRequest;

import com.dyuproject.openid.Constants;
import com.dyuproject.openid.DefaultDiscovery;
import com.dyuproject.openid.DiffieHellmanAssociation;
import com.dyuproject.openid.Identifier;
import com.dyuproject.openid.OpenIdContext;
import com.dyuproject.openid.OpenIdUser;
import com.dyuproject.openid.RelyingParty;
import com.dyuproject.openid.YadisDiscovery;
import com.dyuproject.openid.ext.AxSchemaExtension;
import com.dyuproject.util.http.SimpleHttpConnector;
import com.dyuproject.util.http.UrlEncodedParameterMap;
import com.vaadin.Application;
import com.vaadin.terminal.ExternalResource;
import com.vaadin.terminal.RequestHandler;
import com.vaadin.terminal.Resource;
import com.vaadin.terminal.WrappedRequest;
import com.vaadin.terminal.WrappedResponse;
import com.vaadin.ui.Embedded;

public class OpenIdHandler {
    /**
     * The different pieces of information that the OpenID provider can return
     */
    public enum UserAttribute {
        email, firstname, lastname, country, language, fullname, nickname, dob, gender, postcode, timezone;
    }

    /**
     * Listener for login events
     */
    public interface OpenIdLoginListener {
        /**
         * Called whenever a user has logged in
         * 
         * @param id
         *            the OpenID identification of the logged in user
         * @param userAttributes
         *            additional information about the user. Not yet in use.
         */
        public void onLogin(String id, Map<UserAttribute, String> userAttributes);

        public void onCancel();
    }

    private final String LOGIN_HANDLER_URL = "openidLogin"
            + Math.round(Math.random() * 100000);

    // Used to get a relatively unique url even if the random number in
    // LOGIN_HANDLER_URL collides (and then there would still be different
    // session cookies to isolate different requests)
    private static final AtomicInteger counter = new AtomicInteger(0);

    // Keep a cache of the 50 most recently used discovery results
    private static final Map<String, String> discoveryCache = Collections
            .synchronizedMap(new LinkedHashMap<String, String>(16, 0.75f, true) {
                @Override
                protected boolean removeEldestEntry(
                        Map.Entry<String, String> eldest) {
                    return size() > 50;
                }
            });
    // Everything here seems to be thread safe, so it "should" be ok to share
    // one static instance
    private static final OpenIdContext context = new OpenIdContext(
            new DefaultDiscovery(), new DiffieHellmanAssociation(),
            new SimpleHttpConnector());

    private static final byte[] returnResponse = ("<html><body>Login form handled."
            + "<script type='text/javascript'>if (window.opener && window.opener.vaadin) {window.opener.vaadin.forceSync();window.close()};"
            + "</script></body></html>").getBytes();

    private final Collection<OpenIdLoginListener> listeners = new ArrayList<OpenIdHandler.OpenIdLoginListener>();
    private AxSchemaExtension attributeExchange = null;

    private final RequestHandler requestHandler = new RequestHandler() {
        public boolean handleRequest(Application application,
                WrappedRequest request, WrappedResponse response)
                throws IOException {
            Map<String, String[]> parameters = request.getParameterMap();
            // If we seem to have an openid response, add an uri handler to
            // check the info and give a reasonable response
            String mode = getOpenidMode(parameters);
            if (mode == null) {
                return false;
            }

            String requestPathInfo = request.getRequestPathInfo();
            OpenIdUser openIdUser = openIdUsers.get(requestPathInfo);
            if (openIdUser == null) {
                // Don't return anything if this isn't a url that we
                // have registered
                return false;
            }

            handleLoginRequest(openIdUser, mode, parameters);

            // Return some html that causes the dialog to close and
            // Vaadin in the original window to refresh
            response.setContentType("text/html");
            OutputStream outputStream = response.getOutputStream();
            outputStream.write(returnResponse);
            outputStream.flush();
            return true;
        }
    };

    private final Application application;

    private final Map<String, OpenIdUser> openIdUsers = new HashMap<String, OpenIdUser>();

    private boolean isAttached;

    /**
     * Create a new OpenIdHandler associated with the passed Vaadin Application.
     * 
     * @param application
     *            The Vaadin Application used by this handler.
     */
    public OpenIdHandler(Application application) {
        this.application = application;
        application.addRequestHandler(requestHandler);

        isAttached = true;
    }

    /**
     * Closes the OpenIdHandler, removing all bindings to the associated
     * Application. After closing the handler, it can not be used any more.
     */
    public void close() {
        isAttached = false;
        listeners.clear();
        openIdUsers.clear();
        getApplication().removeRequestHandler(requestHandler);
    }

    protected Application getApplication() {
        return application;
    }

    private void handleLoginRequest(OpenIdUser openIdUser, String mode,
            final Map<String, String[]> parameters) {
        if (!Constants.Mode.ID_RES.equals(mode)) {
            fireCancel();
            return;
        }
        Map<String, String> params = new HashMap<String, String>();
        for (Entry<String, String[]> entry : parameters.entrySet()) {
            params.put(entry.getKey(), entry.getValue()[0]);
        }

        try {
            // TODO Check and cache nonce? Replay should still not be possible
            // as our return urls are more or less unique?
            boolean verifyAuth = context.getAssociation().verifyAuth(
                    openIdUser, params, context);
            if (!verifyAuth) {
                throw new RuntimeException("Could not verify");
            }

        } catch (Exception e) {
            throw new RuntimeException(e);
        }

        Map<UserAttribute, String> userAttributes = new EnumMap<OpenIdHandler.UserAttribute, String>(
                UserAttribute.class);
        if (attributeExchange != null) {
            attributeExchange.onAuthenticate(openIdUser,
                    createParameterRequst(params));
            Map<String, String> extensionValues = AxSchemaExtension
                    .get(openIdUser);
            for (Entry<String, String> entry : extensionValues.entrySet()) {
                UserAttribute attribute = UserAttribute.valueOf(entry.getKey());
                userAttributes.put(attribute, entry.getValue());
            }
        }

        fireLogin(openIdUser.getIdentity(), userAttributes);
    }

    private final HttpServletRequest createParameterRequst(
            final Map<String, String> params) {
        return (HttpServletRequest) Proxy.newProxyInstance(getClass()
                .getClassLoader(), new Class[] { HttpServletRequest.class },
                new InvocationHandler() {
                    public Object invoke(Object proxy, Method method,
                            Object[] args) throws Throwable {
                        if (method.getName().equals("getParameter")) {
                            return params.get(args[0]);
                        } else {
                            throw new RuntimeException(
                                    "Only getParameter handled");
                        }
                    }
                });
    }

    /**
     * Gets a resource for logging in a user with a given OpenID id. For the
     * actual login, the Resource should be opened in an external window or the
     * user should be redirected to the associated URL. Please note that most
     * OpenID providers do not accept logins through iframes (e.g. using
     * {@link Embedded}).
     * 
     * @param id
     *            The OpenID id provided by the user or preselected for a
     *            "Log in using xxx"-button
     * @return A resource that should be opened for the user to log in
     */
    public Resource getLoginResource(String id) {
        if (!isAttached) {
            throw new IllegalStateException("Can not use closed OpenIdHandler");
        }
        Application application = getApplication();
        try {
            Identifier identifier = Identifier.getIdentifier(id, null, context);
            OpenIdUser openIdUser = discover(identifier);
            if (openIdUser == null) {
                throw new RuntimeException("No OpenID provider found for " + id);
            }
            if (!context.getAssociation().associate(openIdUser, context)) {
                throw new RuntimeException("Association failed for " + id);
            }

            String localUrl = LOGIN_HANDLER_URL + "/"
                    + counter.getAndIncrement();

            openIdUsers.put("/" + localUrl, openIdUser);

            String applicationUrl = application.getURL().toString();

            String returnTo = applicationUrl + localUrl;

            // TODO Make this configurable?
            String realm = applicationUrl;

            UrlEncodedParameterMap urlMap = RelyingParty.getAuthUrlMap(
                    openIdUser, realm, realm, returnTo);
            if (attributeExchange != null) {
                attributeExchange.onPreAuthenticate(openIdUser, null, urlMap);
            }

            return new ExternalResource(urlMap.toString());
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private static OpenIdUser discover(Identifier identifier) throws Exception {
        String url = identifier.getUrl();
        String cachedServer = discoveryCache.get(url);
        if (cachedServer != null) {
            return OpenIdUser.populate(url, YadisDiscovery.IDENTIFIER_SELECT,
                    cachedServer);
        }
        OpenIdUser openIdUser = context.getDiscovery().discover(identifier,
                context);
        discoveryCache.put(url, openIdUser.getOpenIdServer());
        return openIdUser;
    }

    /**
     * Add a OpenID login listener that is notified whenever a user logs in.
     * 
     * @param loginListener
     *            the OpenID login listener listening to login events
     */
    public void addListener(OpenIdLoginListener loginListener) {
        listeners.add(loginListener);
    }

    /**
     * Sets the OpenId Attributes that should be requested from the OpenId
     * Provider. The OpenId Provider may not include all requested attributes in
     * its response. The values of the attributes that are returned will be
     * passed as a map to all registered login handlers.
     * 
     * @param attributes
     *            an array of userAttributes
     */
    public void setRequestedAttributes(UserAttribute... attributes) {
        setRequestedAttributes(Arrays.asList(attributes));
    }

    /**
     * Sets the OpenId Attributes that should be requested from the OpenId
     * Provider. The OpenId Provider may not include all requested attributes in
     * its response. The values of the attributes that are returned will be
     * passed as a map to all registered login handlers.
     * 
     * @param attributes
     *            a collection of userAttributes
     */
    public void setRequestedAttributes(Collection<UserAttribute> attributes) {
        if (attributes.isEmpty()) {
            attributeExchange = null;
        } else {
            attributeExchange = new AxSchemaExtension();
            for (UserAttribute field : attributes) {
                attributeExchange.addExchange(field.toString().toLowerCase());
            }
        }
    }

    private static final String getOpenidMode(Map<String, String[]> parameters) {
        String[] modeValues = parameters.get(Constants.OPENID_MODE);
        if (modeValues == null || modeValues.length == 0) {
            // Ignore if it isn't an openid request
            return null;
        }
        return modeValues[0];
    }

    private void fireLogin(String id, Map<UserAttribute, String> userAttributes) {
        for (OpenIdLoginListener l : new ArrayList<OpenIdLoginListener>(
                listeners)) {
            l.onLogin(id, userAttributes);
        }
    }

    private void fireCancel() {
        for (OpenIdLoginListener l : new ArrayList<OpenIdLoginListener>(
                listeners)) {
            l.onCancel();
        }
    }
}
