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
import org.owasp.esapi.waf.actions.BlockAction;
import org.owasp.esapi.waf.actions.DefaultAction;
import org.owasp.esapi.waf.actions.DoNothingAction;
import org.owasp.esapi.waf.business.AppGuardianConfigurationBC;
import org.owasp.esapi.waf.configuration.AppGuardianConfiguration;
import org.owasp.esapi.waf.internal.InterceptingHTTPServletResponse;
import org.owasp.esapi.waf.rules.support.RuleWithAllowDeny;

import br.gov.frameworkdemoiselle.util.Beans;

/**
 * This is the Rule subclass executed for &lt;restrict-user-agent&gt; rules.
 * @author Arshan Dabirsiaghi
 *
 */
@Entity
public class RestrictUserAgentRule extends RuleWithAllowDeny {
	
	@Transient
	private static final long serialVersionUID = 1L;

	@Transient
	private static final String USER_AGENT_HEADER = "User-Agent";
	
	@Transient
	private AppGuardianConfigurationBC appGuardianConfigurationBC;

	public RestrictUserAgentRule(){
		super();
	}

	public RestrictUserAgentRule(String id, Pattern allow, Pattern deny) {
		super(allow, deny);
		setId(id);
	}
	
	private AppGuardianConfiguration getAppGuardianConfiguration(){
		if (appGuardianConfigurationBC == null)
			appGuardianConfigurationBC = Beans.getReference(AppGuardianConfigurationBC.class);
		return appGuardianConfigurationBC.loadSingletonInstance();
	}

	public Action check(HttpServletRequest request, InterceptingHTTPServletResponse response, HttpServletResponse httpResponse) {
		
		String userAgent = request.getHeader( USER_AGENT_HEADER );
		
		if ( userAgent == null ) userAgent="";
		
		if ( getAllow() != null ) {
			if ( getAllow().matches(userAgent) ) {
				return new DoNothingAction();
			}
		} else if ( getDeny() != null ) {
			if ( ! getDeny().matches(userAgent) ) {
				return new DoNothingAction();
			}
		}

		log(request, "Disallowed user agent pattern '" + getDeny().pattern() + "' found in user agent '" + request.getHeader(USER_AGENT_HEADER) + "'");
	
		/*
		 * If we don't force this to "block", the user will be in an infinite loop, possibly
		 * eating our bandwidth, and in the case of a dread false positive, really piss them
		 * off.
		 * 
		 * Better to just reject.
		 */
		if ( getAppGuardianConfiguration().getDefaultFailAction() == AppGuardianConfiguration.REDIRECT ) {
			return new BlockAction();
		}

		return new DefaultAction();
	}
}
