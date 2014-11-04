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

import java.security.Principal;

public class NonceSimplePrincipal implements Principal {

	private String name;
	private String nonce;

	public NonceSimplePrincipal(String name) {
		this.name = name;
	}

	public String getName() {
		return name;
	}

	public String getNonce() {
		return nonce;
	}

	public void setNonce(String nonce) {
		this.nonce = nonce;
	}

	public boolean equals(Object another) {
		if (!(another instanceof NonceSimplePrincipal))
			return false;

		String anotherName = ((NonceSimplePrincipal) another).getName();
		String anotherNonce = ((NonceSimplePrincipal) another).getNonce();
		if (name != null && nonce != null) {
			return name.equals(anotherName) && nonce.equals(anotherNonce);
		}
		if (name == null && nonce == null) {
			return anotherName == null && anotherNonce == null;
		}
		if (name == null && nonce != null) {
			return anotherName == null && nonce.equals(anotherNonce);
		}
		if (name != null && nonce == null) {
			return name.equals(anotherName) && anotherNonce == null;
		}
		return false;
	}

	@Override
	public int hashCode() {
		return (name + nonce == null ? 0 : (name + nonce).hashCode());
	}

	@Override
	public String toString() {
		return name + nonce;
	}

}
