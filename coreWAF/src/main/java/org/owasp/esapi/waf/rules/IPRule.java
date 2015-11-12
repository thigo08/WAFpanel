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
 * This is the Rule subclass executed for &lt;detect-source-ip&gt; rules.
 * @author Arshan Dabirsiaghi
 *
 */
@Entity
public class IPRule extends RuleWithUrlPath {
	
	@Transient
	private static final long serialVersionUID = 1L;

	@OneToOne
	private PatternEntity allowedIP;
			
	private String ipHeader;
			
	public IPRule(){
		super();
		setAllowedIP(new PatternEntity());
	}

	public IPRule(String id, Pattern allowedIP, Pattern path, String ipHeader) {
		super (path);
		this.setAllowedIP(new PatternEntity(allowedIP));		
		this.ipHeader = ipHeader;
		setId(id);
	}

	public IPRule(String id, Pattern allowedIP, String exactPath) {
		super(exactPath);				
		setId(id);
	}

	public Action check(HttpServletRequest request,
			InterceptingHTTPServletResponse response, 
			HttpServletResponse httpResponse) {

		String uri = request.getRequestURI();

		if ( getPath().matches(uri) ) {
			
			String sourceIP = request.getRemoteAddr() + "";
			
			if ( ipHeader != null ) {
				sourceIP = request.getHeader(ipHeader);
			}
			
			if ( ! getAllowedIP().matches(sourceIP) ) {
				log(request, "IP not allowed to access URI '" + uri + "'");
				return new DefaultAction();
			}
		}

		return new DoNothingAction();
	}

	public String getIpHeader() {
		return ipHeader;
	}

	public void setIpHeader(String ipHeader) {
		this.ipHeader = ipHeader;
	}

	public PatternEntity getAllowedIP() {
		return allowedIP;
	}

	public void setAllowedIP(PatternEntity allowedIP) {
		this.allowedIP = allowedIP;
	}
}
