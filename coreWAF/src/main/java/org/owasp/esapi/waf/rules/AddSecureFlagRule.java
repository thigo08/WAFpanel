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
import org.owasp.esapi.waf.actions.DoNothingAction;
import org.owasp.esapi.waf.internal.InterceptingHTTPServletResponse;
import org.owasp.esapi.waf.rules.support.PatternEntity;
import org.owasp.esapi.waf.rules.support.RuleWithPatterns;

/**
 * This is the Rule subclass executed for &lt;add-secure-flag&gt; rules.
 * @author Arshan Dabirsiaghi
 *
 */
@Entity
public class AddSecureFlagRule extends RuleWithPatterns {
	
	@Transient
	private static final long serialVersionUID = 1L;
	
	public AddSecureFlagRule(){
		super();
	}

	public AddSecureFlagRule(String id, List<Pattern> name) {
		setId(id);
		super.fillListOfPatternEntity(name);
	}

	public Action check(HttpServletRequest request,
			InterceptingHTTPServletResponse response, 
			HttpServletResponse httpResponse) {
		
		DoNothingAction action = new DoNothingAction();

		return action;
	}

	public boolean doesCookieMatch(String cookieName) {

		for (PatternEntity p : super.getPatternList()){		
			if ( p.matches(cookieName) ) {
				return true;
			}
		}

		return false;
	}
	
}
