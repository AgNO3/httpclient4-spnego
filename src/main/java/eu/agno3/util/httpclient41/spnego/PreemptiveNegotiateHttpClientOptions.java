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


/**
 * Runtime configurable options for SPNEGO support.
 * 
 * @author Moritz Bechler <bechler@agno3.eu>
 */
public final class PreemptiveNegotiateHttpClientOptions {

    private PreemptiveNegotiateHttpClientOptions () {}

    /**
     * Enable SPNEGO authentication code
     * 
     * @since 1.1
     */
    public static final String ALLOW_SPNEGO_PROP = "eu.agno3.util.httpclient4.spnegoEnable"; //$NON-NLS-1$;

    /**
     * 
     */
    public static final String ALLOW_SPNEGO_PROP_OLD = "eu.agno3.util.httpclient41.spnegoEnable"; //$NON-NLS-1$

    /**
     * Enable SPNEGO for proxy authentication
     * 
     * @since 1.1
     */
    public static final String SPNEGO_PROXY_AUTH_PROP = "eu.agno3.util.httpclient4.spnegoProxyAuth"; //$NON-NLS-1$;

    /**
     * 
     */
    public static final String SPNEGO_PROXY_AUTH_PROP_OLD = "eu.agno3.util.httpclient41.spnegoProxyAuth"; //$NON-NLS-1$

    /**
     * Authentication scopes to perform SPNEGO
     * 
     * Comma separated list of URLs, only port (scheme default if not given) and
     * host is used.
     * 
     * @since 1.1
     */
    public static final String SPNEGO_AUTH_SCOPES_PROP = "eu.agno3.util.httpclient4.spnegoAuthScopes"; //$NON-NLS-1$

    /**
     * 
     */
    public static final String SPNEGO_AUTH_SCOPES_PROP_OLD = "eu.agno3.util.httpclient41.spnegoAuthScopes"; //$NON-NLS-1$


    /**
     * Helper to determine whether negotiate autehentication is enabled
     * 
     * @return whether SPNEGO shall be enabled or not
     */
    public static boolean haveSPNEGOEnabled () {
        return ( System.getProperties().getProperty(ALLOW_SPNEGO_PROP, System.getProperties().getProperty(ALLOW_SPNEGO_PROP_OLD, "false")).equals("true") ); //$NON-NLS-1$ //$NON-NLS-2$
    }
}
