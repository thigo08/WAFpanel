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

import java.util.Enumeration;
import java.util.regex.Pattern;

import javax.persistence.Entity;
import javax.persistence.OneToOne;
import javax.persistence.Transient;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.owasp.esapi.waf.actions.Action;
import org.owasp.esapi.waf.actions.DefaultAction;
import org.owasp.esapi.waf.actions.DoNothingAction;
import org.owasp.esapi.waf.internal.InterceptingHTTPServletRequest;
import org.owasp.esapi.waf.internal.InterceptingHTTPServletResponse;
import org.owasp.esapi.waf.rules.support.PatternEntity;

/**
 * This is the Rule subclass executed for &lt;general-attack-signature&gt; rules, which 
 * are not currently implemented.
 * @author Arshan Dabirsiaghi
 *
 */
@Entity
public class GeneralAttackSignatureRule extends Rule {
	
	@Transient
	private static final long serialVersionUID = 1L;
	
	@OneToOne
	private PatternEntity signature;
	
	public GeneralAttackSignatureRule(){
		super();
		signature = new PatternEntity();
	}

	public GeneralAttackSignatureRule(String id, Pattern signature) {
		this.setSignature(new PatternEntity(signature));
		setId(id);
	}

	public Action check(HttpServletRequest req,
			InterceptingHTTPServletResponse response, 
			HttpServletResponse httpResponse) {

		InterceptingHTTPServletRequest request = (InterceptingHTTPServletRequest)req;
		Enumeration e = request.getParameterNames();

		while(e.hasMoreElements()) {
			String param = (String)e.nextElement();
			if ( signature.matches(request.getDictionaryParameter(param)) ) {
				log(request,"General attack signature detected in parameter '" + param + "' value '" + request.getDictionaryParameter(param) + "'");
				return new DefaultAction();
			}
		}

		return new DoNothingAction();
	}

	public PatternEntity getSignature() {
		return signature;
	}

	public void setSignature(PatternEntity signature) {
		this.signature = signature;
	}

}
