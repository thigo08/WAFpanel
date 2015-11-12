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

import javax.persistence.Entity;
import javax.persistence.Transient;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.owasp.esapi.waf.actions.Action;
import org.owasp.esapi.waf.actions.DefaultAction;
import org.owasp.esapi.waf.actions.DoNothingAction;
import org.owasp.esapi.waf.internal.InterceptingHTTPServletResponse;
import org.owasp.esapi.waf.rules.support.RuleWithAllowDeny;

/**
 * This is the Rule subclass executed for &lt;dynamic-insertion&gt; rules.
 * @author Arshan Dabirsiaghi
 *
 */
@Entity
public class RestrictContentTypeRule extends RuleWithAllowDeny {
	
	@Transient
	private static final long serialVersionUID = 1L;
	
	public RestrictContentTypeRule(){
		super();
	}

	public RestrictContentTypeRule(String id, Pattern allow, Pattern deny) {
		super(allow, deny);
		setId(id);
	}

	public Action check(HttpServletRequest request,
			InterceptingHTTPServletResponse response, 
			HttpServletResponse httpResponse) {

		/* can't check content type if it's not available */
		if ( request.getContentType() == null ) {
			return new DoNothingAction();
		}

		if ( getAllow() != null ) {
			if ( getAllow().matches(request.getContentType()) ) {
				return new DoNothingAction();
			}
			log(request, "Disallowed content type based on allow pattern '" + getAllow().pattern() + "' found on URI '" + request.getRequestURI() + "' (value was '" + request.getContentType() +"')");
		} else if ( getDeny() != null ) {
			if ( ! getDeny().matches(request.getContentType()) ) {
				return new DoNothingAction();
			}
			log(request, "Disallowed content type based on deny pattern '" + getDeny().pattern() + "' found on URI '" + request.getRequestURI() + "' (value was '" + request.getContentType() + ")'");
		}


		return new DefaultAction();

	}
}
