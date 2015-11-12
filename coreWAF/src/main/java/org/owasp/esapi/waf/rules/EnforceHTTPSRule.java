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

import org.owasp.esapi.waf.actions.Action;
import org.owasp.esapi.waf.actions.DefaultAction;
import org.owasp.esapi.waf.actions.DoNothingAction;
import org.owasp.esapi.waf.actions.RedirectAction;
import org.owasp.esapi.waf.internal.InterceptingHTTPServletResponse;
import org.owasp.esapi.waf.rules.support.RuleWithExceptions;
import org.owasp.esapi.waf.rules.support.UrlPath;

/**
 * This is the Rule subclass executed for &lt;enforce-https&gt; rules.
 * @author Arshan Dabirsiaghi
 *
 */
@Entity
public class EnforceHTTPSRule extends RuleWithExceptions {

	@Transient
	private static final long serialVersionUID = 1L;
	
	private String action;

	/*
	 * action = [ redirect | block ] [=default (redirect will redirect to error page]
	 */

	public EnforceHTTPSRule(){
		super();
	}
	
	public EnforceHTTPSRule(String id, Pattern path, List<Object> exceptions, String action) {
		super(path);
		super.fillExceptionsWithListOfObjects(exceptions);
		this.action = action;
		setId(id);
	}

	public Action check(HttpServletRequest request,
			InterceptingHTTPServletResponse response, 
			HttpServletResponse httpResponse) {

		if ( ! request.isSecure() ) {

			if ( getPath().matches(request.getRequestURI()) ) {

				for (UrlPath path : getExceptions()) {			
					if (path.matches(request.getRequestURI()))
						return new DoNothingAction();
				}

				log(request,"Insecure request to resource detected in URL: '" + request.getRequestURL() + "'");

				if ( "redirect".equals(action) ) {
					RedirectAction ra = new RedirectAction();
					ra.setRedirectURL(request.getRequestURL().toString().replaceFirst("http", "https"));
					return ra;
				}

				return new DefaultAction();

			}
		}

		return new DoNothingAction();

	}

	public String getAction() {
		return action;
	}

	public void setAction(String action) {
		this.action = action;
	}

}
