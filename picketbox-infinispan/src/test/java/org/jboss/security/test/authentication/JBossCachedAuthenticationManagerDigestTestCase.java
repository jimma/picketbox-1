/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2014, Red Hat Middleware LLC, and individual contributors
 * as indicated by the @author tags. See the copyright.txt file in the
 * distribution for a full listing of individual contributors.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, write to the Free
 * Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA, or see the FSF site: http://www.fsf.org.
 */
package org.jboss.security.test.authentication;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.security.SecureRandom;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.HashMap;
import java.util.TimeZone;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.AppConfigurationEntry;
import javax.security.auth.login.AppConfigurationEntry.LoginModuleControlFlag;
import javax.security.auth.login.Configuration;
import javax.security.jacc.PolicyContext;

import junit.framework.TestCase;

import org.jboss.security.Base64Encoder;
import org.jboss.security.Base64Utils;
import org.jboss.security.SecurityConstants;
import org.jboss.security.auth.callback.CallbackHandlerPolicyContextHandler;
import org.jboss.security.auth.callback.JBossCallbackHandler;
import org.jboss.security.auth.callback.MapCallback;
import org.jboss.security.authentication.JBossCachedAuthenticationManager;
import org.jboss.security.authentication.JBossCachedAuthenticationManager.DomainInfo;

public class JBossCachedAuthenticationManagerDigestTestCase extends TestCase
{
	   private SecureRandom random;
	   private DateFormat dataFormat;
	   private JBossCachedAuthenticationManager digestAm;
	   private JBossCachedAuthenticationManager plainAm;
	   @Override
	   protected void setUp() throws Exception
	   {
	      super.setUp();
	      random = SecureRandom.getInstance("SHA1PRNG");
	      dataFormat = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'");
	      dataFormat.setTimeZone(TimeZone.getTimeZone("UTC"));
	      establishSecurityConfiguration();
	      PolicyContext.registerHandler(SecurityConstants.CALLBACK_HANDLER_KEY, new CallbackHandlerPolicyContextHandler(), true);
	      digestAm = new JBossCachedAuthenticationManager("digest", new JBossCallbackHandler());
	      ConcurrentMap<Principal, DomainInfo> map = new ConcurrentHashMap<Principal, DomainInfo>();
	      digestAm.setCache(map);
	      plainAm = new JBossCachedAuthenticationManager("plain", new JBossCallbackHandler());
	      plainAm.setCache(new ConcurrentHashMap<Principal, DomainInfo>());
	   }

	   private void establishSecurityConfiguration()
	   {
	      SecurityActions.setJAASConfiguration((Configuration) new DigestConfig());
	   }
	   
	   public void testAuthenticate() throws Exception
	   {
		   ExecutorService service = Executors.newFixedThreadPool(10);
		   for (int i = 0 ; i < 100; i ++ ){
			   service.execute( new AuthenticatonRunnable());
		   }
		   service.shutdown();
		   service.awaitTermination(1, TimeUnit.MINUTES);
		   assertEquals("Cahced key number is not exepcted", 100, digestAm.getCachedKeys().size());
		
	   }
	   
	   public boolean authenticate(Principal principal, Object credential, Subject subject, String securityDomain) {
		   if ("digest".equals(securityDomain)) {
			   return digestAm.isValid(principal, credential, subject);
		   } else {
			   return plainAm.isValid(principal, credential, subject);
		   }
	   }
	   

	   private String getNonce() {
		byte[] temp = new byte[16];
		random.nextBytes(temp);
	 	return Base64Utils.tob64(temp);
	   }
	   private String getCreated() {
		   Date currentTime = new Date();
		  String created = dataFormat.format(currentTime);
		  return created;
	   }
	   
	   public class AuthenticatonRunnable implements Runnable {

		public void run() {
			String nonce = getNonce();
			String created = getCreated();
			NonceSimplePrincipal noncePrincipal = new NonceSimplePrincipal("jduke");
			noncePrincipal.setNonce(nonce);
			
			Subject activeSubject = new Subject();
			Object credential = doPasswordDigest(nonce, created, "theduke".getBytes());
			try {
				CallbackHandler handler = new UsernameTokenCallbackHandler(nonce, created, true);
				CallbackHandlerPolicyContextHandler.setCallbackHandler(handler);
				assertTrue("Authentication should be passed", authenticate(noncePrincipal, credential, activeSubject, "digest"));
			} finally {
				CallbackHandlerPolicyContextHandler.setCallbackHandler(null);
			}
			
		}
		   
	   }

	   public class DigestConfig extends Configuration
	   {
	      @Override
	      public AppConfigurationEntry[] getAppConfigurationEntry(String name)
	      {  AppConfigurationEntry ace = null;
	    	 if ("digest".equals(name)) {
	         HashMap<String, Object> map = new HashMap<String, Object>();
	         map.put("usersProperties", "users.properties");
	         map.put("rolesProperties", "roles.properties");
	         map.put("hashAlgorithm", "SHA-1");
	         map.put("hashEncoding", "BASE64");
	         map.put("hashUserPassword", "false");
	         map.put("hashStorePassword", "true");
	         map.put("storeDigestCallback", DigestCallbackImpl.class.getName());
	         String moduleName = "org.jboss.security.auth.spi.UsersRolesLoginModule";
	         ace = new AppConfigurationEntry(moduleName, LoginModuleControlFlag.REQUIRED, map);
	      } else {
	    	  HashMap<String, Object> map = new HashMap<String, Object>();
	          map.put("usersProperties", "users.properties");
	          map.put("rolesProperties", "roles.properties");
	          String moduleName = "org.jboss.security.auth.spi.UsersRolesLoginModule";
	          ace = new AppConfigurationEntry(moduleName, LoginModuleControlFlag.REQUIRED, map);
	      }
	         return new AppConfigurationEntry[]
	         {ace};
	      }

	      @Override
	      public void refresh()
	      {
	      }
	   }
	   
	   
	   
	    public static String doPasswordDigest(String nonce, String created, byte[] password) {
	    	String passwdDigest = null;
			try {
				MessageDigest md = MessageDigest.getInstance("SHA-1");
				md.update(Base64Utils.fromb64(nonce));
		    	md.update(created.getBytes("UTF-8"));
		    	md.update(password);
		    	passwdDigest = Base64Encoder.encode(md.digest());
			} catch (NoSuchAlgorithmException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (UnsupportedEncodingException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
	    	
	        
	        return passwdDigest;
	    }
	   
	   public class UsernameTokenCallbackHandler implements CallbackHandler
	   {
		   private final String nonce;

		   private final String created;

		   private final boolean decodeNonce;

		   public UsernameTokenCallbackHandler(String nonce, String created, boolean decodeNonce)
		   {
		      this.created = created;
		      this.nonce = nonce;
		      this.decodeNonce = decodeNonce;
		   }

		   public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException
		   {
		      boolean foundCallback = false;
		      Callback firstUnknown = null;
		      int count = callbacks != null ? callbacks.length : 0;
		      for (int n = 0; n < count; n++)
		      {
		         Callback c = callbacks[n];
		         if (c instanceof MapCallback)
		         {
		            //set parameters to the MapCallback the UsernameTokenCallback
		            //created and set up in the init method
		            MapCallback mc = (MapCallback) c;
		            mc.setInfo("nonce", nonce);
		            mc.setInfo("created", created);
		            mc.setInfo("decodeNonce", Boolean.valueOf(decodeNonce));
		            foundCallback = true;
		         }
		         else if (firstUnknown == null)
		         {
		            firstUnknown = c;
		         }
		      }
		      if (foundCallback == false)
		         throw new UnsupportedCallbackException(firstUnknown, "Unrecognized Callback");
		   }

		}
}
