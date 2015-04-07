/**
 * © 2015 AgNO3 Gmbh & Co. KG
 * All right reserved.
 * 
 * Created: 15.02.2015 by mbechler
 */
package eu.agno3.util.httpclient41.spnego;


import java.net.MalformedURLException;
import java.net.URL;
import java.util.HashSet;
import java.util.Set;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.auth.AuthSchemeProvider;
import org.apache.http.auth.AuthScope;
import org.apache.http.client.config.AuthSchemes;
import org.apache.http.config.Lookup;
import org.apache.http.config.RegistryBuilder;
import org.apache.http.impl.auth.BasicSchemeFactory;
import org.apache.http.impl.auth.DigestSchemeFactory;
import org.apache.http.impl.auth.KerberosSchemeFactory;
import org.apache.http.impl.auth.NTLMSchemeFactory;
import org.apache.http.impl.auth.SPNegoSchemeFactory;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;


/**
 * @author mbechler
 *
 */
public class PreemptiveNegotiateHttpClientBuilder {

    private static final String TRUE = "true"; //$NON-NLS-1$
    private static final String FALSE = "false"; //$NON-NLS-1$
    private static final String SCOPES_SEP = ","; //$NON-NLS-1$
    static final String NEGOTIATE_SCHEME = "Negotiate"; //$NON-NLS-1$

    static final Log LOG = LogFactory.getLog(PreemptiveNegotiateHttpClientBuilder.class);


    /**
     * 
     * @param b
     * @return
     */
    public static CloseableHttpClient configure ( HttpClientBuilder b ) {

        String confProxyAuth = System.getProperty(
            PreemptiveNegotiateHttpClientOptions.SPNEGO_PROXY_AUTH_PROP,
            System.getProperty(PreemptiveNegotiateHttpClientOptions.SPNEGO_PROXY_AUTH_PROP_OLD, FALSE));
        String confAuthScopes = System.getProperty(
            PreemptiveNegotiateHttpClientOptions.SPNEGO_AUTH_SCOPES_PROP,
            System.getProperty(PreemptiveNegotiateHttpClientOptions.SPNEGO_AUTH_SCOPES_PROP_OLD, "")); //$NON-NLS-1$

        boolean stripPort = true;
        boolean doProxySpnegoAuth = false;

        if ( confProxyAuth.equals(TRUE) ) {
            doProxySpnegoAuth = true;
        }

        String[] scopes = confAuthScopes.split(SCOPES_SEP);
        Set<AuthScope> authScopes = new HashSet<AuthScope>();

        for ( int i = 0; i < scopes.length; i++ ) {
            String scope = scopes[ i ];
            if ( scope.trim().length() == 0 ) {
                continue;
            }

            try {
                URL scopeURL = new URL(scope);
                addSPNEGOAuthScope(scopeURL, authScopes);
            }
            catch ( MalformedURLException e ) {
                LOG.error("Failed to add scope:", e); //$NON-NLS-1$
            }

        }

        b.addInterceptorFirst(new InitAuthCacheInterceptor(stripPort, doProxySpnegoAuth, authScopes));
        b.setDefaultAuthSchemeRegistry(makeAuthSchemeRegistry(stripPort));
        return b.build();
    }


    /**
     * 
     * @param url
     */
    private static void addSPNEGOAuthScope ( URL url, Set<AuthScope> scopes ) {
        int port = -1;
        if ( url.getPort() == -1 ) {
            port = url.getPort();
        }
        else {
            port = url.getDefaultPort();
        }

        LOG.debug("SPNEGO Authentication enabled for " + url.getHost()); //$NON-NLS-1$
        scopes.add(new AuthScope(url.getHost(), port, AuthScope.ANY_REALM, NEGOTIATE_SCHEME));
    }


    /**
     * @return
     */
    private static Lookup<AuthSchemeProvider> makeAuthSchemeRegistry ( boolean stripPort ) {
        return RegistryBuilder.<AuthSchemeProvider> create().register(AuthSchemes.BASIC, new BasicSchemeFactory())
                .register(AuthSchemes.DIGEST, new DigestSchemeFactory()).register(AuthSchemes.NTLM, new NTLMSchemeFactory())
                .register(AuthSchemes.SPNEGO, new SPNegoSchemeFactory(stripPort))
                .register(AuthSchemes.KERBEROS, new KerberosSchemeFactory(stripPort)).build();
    }
}
