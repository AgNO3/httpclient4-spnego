/****************************************************************************
 * Copyright (c) 2013 AgNO3 GmbH & Co. KG.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Contributors:
 * 		Moritz Bechler, AgNO3 - Initial Implementation of SPNEGO support 
 *****************************************************************************/
package eu.agno3.util.httpclient41.spnego;


import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.HttpHost;
import org.apache.http.auth.AuthScheme;
import org.apache.http.auth.MalformedChallengeException;
import org.apache.http.impl.auth.SPNegoScheme;
import org.apache.http.impl.client.BasicAuthCache;
import org.apache.http.message.BasicHeader;


/**
 * Fake authentication cache always returning a new PerRequestNegotiateScheme
 * 
 * This auth cache returns a new PreemptiveNegotiateScheme for both the host
 * specified as targetHost and proxyHost. Other credentials remain unaffected.
 * 
 * The NegotiateScheme is initialized with an empty Negotiate challenge to
 * prepare for preemptive authentication.
 * 
 * @author Moritz Bechler <bechler@agno3.eu>
 */
public class PreemptiveNegotiateAuthCache extends BasicAuthCache {

    private static final Log log = LogFactory.getLog(PreemptiveNegotiateAuthCache.class);

    private HttpHost targetHost;
    private HttpHost proxyHost;

    private boolean stripPort;


    /**
     * @param stripPort
     * @param targetHost
     * @param proxyHost
     */
    public PreemptiveNegotiateAuthCache ( boolean stripPort, HttpHost targetHost, HttpHost proxyHost ) {
        super();
        this.stripPort = stripPort;
        this.targetHost = targetHost;
        this.proxyHost = proxyHost;
    }


    @Override
    public AuthScheme get ( HttpHost host ) {
        if ( this.targetHost != null && this.targetHost.equals(host) ) {
            AuthScheme scheme = new SPNegoScheme(this.stripPort);
            try {
                scheme.processChallenge(new BasicHeader("WWW-Authenticate", "Negotiate")); //$NON-NLS-1$//$NON-NLS-2$
            }
            catch ( MalformedChallengeException e ) {
                log.warn("Failed to process fake initial challenge:", e); //$NON-NLS-1$
            }
            log.debug("Returning PerRequestNegotiateScheme for host"); //$NON-NLS-1$
            return scheme;
        }
        else if ( this.proxyHost != null && this.proxyHost.equals(host) ) {
            AuthScheme scheme = new SPNegoScheme(this.stripPort);
            try {
                scheme.processChallenge(new BasicHeader("Proxy-Authenticate", "Negotiate")); //$NON-NLS-1$//$NON-NLS-2$
            }
            catch ( MalformedChallengeException e ) {
                log.warn("Failed to process fake initial challenge:", e); //$NON-NLS-1$
            }
            return scheme;
        }

        return super.get(host);
    }


    @Override
    public void put ( HttpHost host, AuthScheme authScheme ) {
        if ( host.equals(this.targetHost) || host.equals(this.proxyHost) ) {
            return;
        }
        super.put(host, authScheme);
    }
}
