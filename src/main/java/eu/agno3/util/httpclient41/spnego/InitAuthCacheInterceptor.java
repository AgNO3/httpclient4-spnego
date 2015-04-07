/**
 * © 2015 AgNO3 Gmbh & Co. KG
 * All right reserved.
 * 
 * Created: 15.02.2015 by mbechler
 */
package eu.agno3.util.httpclient41.spnego;


import java.io.IOException;
import java.util.Set;

import org.apache.http.HttpException;
import org.apache.http.HttpHost;
import org.apache.http.HttpRequest;
import org.apache.http.HttpRequestInterceptor;
import org.apache.http.auth.AuthScheme;
import org.apache.http.auth.AuthScope;
import org.apache.http.auth.AuthState;
import org.apache.http.auth.Credentials;
import org.apache.http.auth.MalformedChallengeException;
import org.apache.http.client.AuthCache;
import org.apache.http.client.protocol.HttpClientContext;
import org.apache.http.impl.auth.SPNegoScheme;
import org.apache.http.message.BasicHeader;
import org.apache.http.protocol.HttpContext;


/**
 * @author mbechler
 *
 */
public class InitAuthCacheInterceptor implements HttpRequestInterceptor {

    private final boolean doProxySpnegoAuth;
    private final Set<AuthScope> authScopes;
    private boolean stripPort;


    /**
     * @param stripPort
     * @param doProxySpnegoAuth
     * @param authScopes
     * 
     */
    public InitAuthCacheInterceptor ( boolean stripPort, boolean doProxySpnegoAuth, Set<AuthScope> authScopes ) {
        this.stripPort = stripPort;
        this.doProxySpnegoAuth = doProxySpnegoAuth;
        this.authScopes = authScopes;
    }


    protected boolean doSPNEGOProxyAuth () {
        return this.doProxySpnegoAuth;
    }


    protected boolean doSPNEGOForScope ( AuthScope scope ) {
        return this.authScopes.contains(scope);
    }


    /**
     * @throws HttpException
     * @throws IOException
     */
    @Override
    public void process ( HttpRequest req, HttpContext context ) throws HttpException, IOException {

        HttpClientContext clientContext = new HttpClientContext(context);
        AuthCache authCache = clientContext.getAuthCache();
        HttpHost targetHost = clientContext.getTargetHost();
        HttpHost proxyHost = clientContext.getHttpRoute().getProxyHost();

        AuthScope targetAuthScope = new AuthScope(
            targetHost.getHostName(),
            targetHost.getPort(),
            AuthScope.ANY_REALM,
            PreemptiveNegotiateHttpClientBuilder.NEGOTIATE_SCHEME);

        if ( authCache == null && ( this.doProxySpnegoAuth || doSPNEGOForScope(targetAuthScope) ) ) {
            PreemptiveNegotiateHttpClientBuilder.LOG.debug("Initialize auth cache using FakeNegotiateAuthCache"); //$NON-NLS-1$
            context.setAttribute(HttpClientContext.AUTH_CACHE, new PreemptiveNegotiateAuthCache(this.stripPort, targetHost, proxyHost));
        }

        if ( proxyHost != null && this.doProxySpnegoAuth ) {
            PreemptiveNegotiateHttpClientBuilder.LOG.debug("Preemptively setting proxy credentials"); //$NON-NLS-1$
            final Credentials proxyCredentials = new JAASCredentials();
            AuthState proxyState = (AuthState) context.getAttribute(HttpClientContext.PROXY_AUTH_STATE);
            AuthScheme proxyScheme = new SPNegoScheme(this.stripPort);
            try {
                proxyScheme.processChallenge(new BasicHeader("Proxy-Authenticate", PreemptiveNegotiateHttpClientBuilder.NEGOTIATE_SCHEME)); //$NON-NLS-1$
            }
            catch ( MalformedChallengeException e ) {
                PreemptiveNegotiateHttpClientBuilder.LOG.error("Could not initialize Negotiate scheme", e); //$NON-NLS-1$
            }
            proxyState.update(proxyScheme, proxyCredentials);
        }

        if ( doSPNEGOForScope(targetAuthScope) ) {
            PreemptiveNegotiateHttpClientBuilder.LOG.debug("Preemptively setting target credentials"); //$NON-NLS-1$
            final Credentials targetCredentials = new JAASCredentials();
            AuthState targetState = (AuthState) context.getAttribute(HttpClientContext.TARGET_AUTH_STATE);
            AuthScheme targetScheme = new SPNegoScheme(this.stripPort);
            try {
                targetScheme.processChallenge(new BasicHeader("WWW-Authenticate", PreemptiveNegotiateHttpClientBuilder.NEGOTIATE_SCHEME)); //$NON-NLS-1$
            }
            catch ( MalformedChallengeException e ) {
                PreemptiveNegotiateHttpClientBuilder.LOG.error("Could not initialize Negotiate scheme", e); //$NON-NLS-1$
            }

            targetState.update(targetScheme, targetCredentials);
        }
    }
}