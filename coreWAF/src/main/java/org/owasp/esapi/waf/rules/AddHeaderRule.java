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
import org.owasp.esapi.waf.rules.support.RuleWithExceptions;
import org.owasp.esapi.waf.rules.support.UrlPath;

/**
 * This is the Rule subclass executed for &lt;add-header&gt; rules.
 * @author Arshan Dabirsiaghi
 *
 */
@Entity
public class AddHeaderRule extends RuleWithExceptions {

	@Transient
	private static final long serialVersionUID = 1L;
		
	private String header;
	private String value;

	public AddHeaderRule(){
		super();
	}

	public AddHeaderRule(String id, String header, String value, Pattern path, List<Object> exceptions) {
		super(path);
		setId(id);
		this.header = header;
		this.value = value;		
		super.fillExceptionsWithListOfObjects(exceptions);
	}

	public Action check(
			HttpServletRequest request, 
			InterceptingHTTPServletResponse response, 
			HttpServletResponse httpResponse) {

		DoNothingAction action = new DoNothingAction();

		if ( getPath().matches(request.getRequestURI()) ) {

			//for(int i=0;i<getExceptions().size();i++) {
			for (UrlPath exception : getExceptions()){
				if (exception.matches(request.getRequestURI())){
					action.setFailed(false);
					action.setActionNecessary(false);
					return action;
				}
			}


			action.setFailed(true);
			action.setActionNecessary(false);

			if ( response != null ) {
				response.setHeader(header, value);
			} else {
				httpResponse.setHeader(header, value);
			}

		}

		return action;
	}

	public String getHeader() {
		return header;
	}

	public void setHeader(String header) {
		this.header = header;
	}

	public String getValue() {
		return value;
	}

	public void setValue(String value) {
		this.value = value;
	}

}
