/**
 * © 2015 AgNO3 Gmbh & Co. KG
 * All right reserved.
 * 
 * Created: 15.02.2015 by mbechler
 */
package eu.agno3.util.httpclient41.spnego;

import java.security.Principal;

import org.apache.http.auth.Credentials;

class JAASCredentials implements Credentials {

    /**
     * 
     */
    public JAASCredentials () {}


    @Override
    public String getPassword () {
        return null;
    }


    @Override
    public Principal getUserPrincipal () {
        return null;
    }

}