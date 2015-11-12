/**
 * OWASP Enterprise Security API (ESAPI)
 * 
 * This file is part of the Open Web Application Security Project (OWASP)
 * Enterprise Security API (ESAPI) project. For details, please see
 * <a href="http://www.owasp.org/index.php/ESAPI">http://www.owasp.org/index.php/ESAPI</a>.
 *
 * Copyright (c) 2009 - The OWASP Foundation
 * 
 * The ESAPI is published by OWASP under the BSD license. You should read and accept the
 * LICENSE before you use, modify, and/or redistribute this software.
 * 
 * @author Arshan Dabirsiaghi <a href="http://www.aspectsecurity.com">Aspect Security</a>
 * @created 2009
 */
package org.owasp.esapi.waf.rules;

import java.util.regex.Pattern;

import javax.persistence.CascadeType;
import javax.persistence.Entity;
import javax.persistence.OneToOne;
import javax.persistence.Transient;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.owasp.esapi.waf.actions.Action;
import org.owasp.esapi.waf.actions.DefaultAction;
import org.owasp.esapi.waf.actions.DoNothingAction;
import org.owasp.esapi.waf.internal.InterceptingHTTPServletResponse;
import org.owasp.esapi.waf.rules.support.PatternEntity;
import org.owasp.esapi.waf.rules.support.RuleWithUrlPath;

/**
 * This is the Rule subclass executed for &lt;restrict-method&gt; rules.
 * @author Arshan Dabirsiaghi
 *
 */
@Entity
public class HTTPMethodRule extends RuleWithUrlPath {
	
	@Transient
	private static final long serialVersionUID = 1L;

	@OneToOne(cascade = {CascadeType.ALL})
	private PatternEntity allowedMethods;
	
	@OneToOne(cascade = {CascadeType.ALL})
	private PatternEntity deniedMethods;
			
	public HTTPMethodRule (){
		super();
		setAllowedMethods(new PatternEntity());
		setDeniedMethods(new PatternEntity());		
	}

	public HTTPMethodRule(String id, Pattern allowedMethods, Pattern deniedMethods, Pattern path) {
		super (path);
		this.setAllowedMethods(new PatternEntity(allowedMethods));
		this.setDeniedMethods(new PatternEntity(deniedMethods));		
		setId(id);
	}

	public Action check(HttpServletRequest request,
			InterceptingHTTPServletResponse response, 
			HttpServletResponse httpResponse) {

		/*
		 * If no path is specified, apply rule globally.
		 */
		String uri = request.getRequestURI();
		String method = request.getMethod();

		if ( getPath() == null || getPath().matches(uri) ) {
			/*
			 *	Order allow, deny.
			 */

			if ( getAllowedMethods() != null && getAllowedMethods().matches(method) ) {
				return new DoNothingAction();
			} else if ( getAllowedMethods() != null ) {
				log(request,"Disallowed HTTP method '" + request.getMethod() + "' found for URL: " + request.getRequestURL());
				return new DefaultAction();
			}

			if ( getDeniedMethods() != null && getDeniedMethods().matches(method) ) {
				log(request,"Disallowed HTTP method '" + request.getMethod() + "' found for URL: " + request.getRequestURL());
				return new DefaultAction();
			}

		}

		return new DoNothingAction();
	}

	public PatternEntity getAllowedMethods() {
		return allowedMethods;
	}

	public void setAllowedMethods(PatternEntity allowedMethods) {
		this.allowedMethods = allowedMethods;
	}

	public PatternEntity getDeniedMethods() {
		return deniedMethods;
	}

	public void setDeniedMethods(PatternEntity deniedMethods) {
		this.deniedMethods = deniedMethods;
	}
}
