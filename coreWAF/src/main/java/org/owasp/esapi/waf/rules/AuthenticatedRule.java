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

import java.util.List;
import java.util.regex.Pattern;

import javax.persistence.Entity;
import javax.persistence.Transient;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.owasp.esapi.waf.actions.Action;
import org.owasp.esapi.waf.actions.DefaultAction;
import org.owasp.esapi.waf.actions.DoNothingAction;
import org.owasp.esapi.waf.internal.InterceptingHTTPServletResponse;
import org.owasp.esapi.waf.rules.support.RuleWithExceptions;
import org.owasp.esapi.waf.rules.support.UrlPath;

/**
 * This is the Rule subclass executed for &lt;authentication-rules&gt; rules.
 * @author Arshan Dabirsiaghi
 *
 */
@Entity
public class AuthenticatedRule extends RuleWithExceptions {
	
	@Transient
	private static final long serialVersionUID = 1L;
	
	private String sessionAttribute;
	
	public AuthenticatedRule(){
		super();
	}

	public AuthenticatedRule(String id, String sessionAttribute, Pattern path, List<Object> exceptions) {
		super (path);
		this.sessionAttribute = sessionAttribute;
		super.fillExceptionsWithListOfObjects(exceptions);
		setId(id);
	}

	public Action check(HttpServletRequest request,
			InterceptingHTTPServletResponse response, 
			HttpServletResponse httpResponse) {

		HttpSession session = request.getSession();
		String uri = request.getRequestURI();
				
		if ( getPath() != null && ! getPath().matches(uri) ) {
			return new DoNothingAction();
		}

		if ( session != null && session.getAttribute(getSessionAttribute()) != null ) {

			return new DoNothingAction();

		} else { /* check if it's one of the exceptions */
			
			for (UrlPath path : getExceptions()) {			
				if (path.matches(uri))
					return new DoNothingAction();
			}
		}

		log(request, "User requested unauthenticated access to URI '" + request.getRequestURI() + "' [querystring="+request.getQueryString()+"]");

		return new DefaultAction();
	}

	public String getSessionAttribute() {
		return sessionAttribute;
	}

	public void setSessionAttribute(String sessionAttribute) {
		this.sessionAttribute = sessionAttribute;
	}
}
