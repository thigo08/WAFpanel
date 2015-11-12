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
import org.owasp.esapi.waf.rules.support.RuleWithUrlPath;

/**
 * This is the Rule subclass executed for &lt;virtual-patch&gt; rules.
 * @author Arshan Dabirsiaghi
 *
 */
@Entity
public class SimpleVirtualPatchRule extends RuleWithUrlPath {
	
	@Transient
	private static final long serialVersionUID = 1L;

	@Transient
	private static final String REQUEST_PARAMETERS = "request.parameters.";
	@Transient
	private static final String REQUEST_HEADERS = "request.headers.";

	
	private String variable;
	
	@OneToOne
	private PatternEntity valid;
	
	private String message;

	
	public SimpleVirtualPatchRule(){
		super();
		valid = new PatternEntity();
	}

	public SimpleVirtualPatchRule(String id, Pattern path, String variable, Pattern valid, String message) {
		super(path);
		setId(id);
		this.variable = variable;
		this.setValid(new PatternEntity(valid));
		this.message = message;
	}

	public Action check(HttpServletRequest req,
			InterceptingHTTPServletResponse response, 
			HttpServletResponse httpResponse) {

		InterceptingHTTPServletRequest request = (InterceptingHTTPServletRequest)req;

		String uri = request.getRequestURI();
		if ( ! getPath().matches(uri) ) {

			return new DoNothingAction();

		} else {

			/*
			 * Decide which parameters/headers to act on.
			 */
			String target = null;
			Enumeration en = null;
			boolean parameter = true;

			if ( variable.startsWith(REQUEST_PARAMETERS)) {

				target = variable.substring(REQUEST_PARAMETERS.length());
				en = request.getParameterNames();

			} else if ( variable.startsWith(REQUEST_HEADERS) ) {

				parameter = false;
				target = variable.substring(REQUEST_HEADERS.length());
				en = request.getHeaderNames();

			} else {
				log(request, "Patch failed (improperly configured variable '" + variable + "')");
				return new DefaultAction();
			}

			/*
			 * If it contains a regex character, it's a regex. Loop through elements and grab any matches.
			 */
			if ( target.contains("*") || target.contains("?") ) {

				target = target.replaceAll("\\*", ".*");
				Pattern p = Pattern.compile(target);
				while (en.hasMoreElements() ) {
					String s = (String)en.nextElement();
					String value = null;
					if ( p.matcher(s).matches() ) {
						if ( parameter ) {
							value = request.getDictionaryParameter(s);
						} else {
							value = request.getHeader(s);
						}
						if ( value != null && ! valid.matches(value) ) {
							log(request, "Virtual patch tripped on variable '" + variable + "' (specifically '" + s + "'). User input was '" + value + "' and legal pattern was '" + valid.pattern() + "': " + message);
							return new DefaultAction();
						}
					}
				}
				
				return new DoNothingAction();

			} else {

				if ( parameter ) {
					String value = request.getDictionaryParameter(target);
					if ( value == null || valid.matches(value) ) {
						return new DoNothingAction();
					} else {
						log(request, "Virtual patch tripped on parameter '" + target + "'. User input was '" + value + "' and legal pattern was '" + valid.pattern() + "': " + message);
						return new DefaultAction();
					}
				} else {
					String value = request.getHeader(target);
					if ( value == null || valid.matches(value) ) {
						return new DoNothingAction();
					} else {
						log(request, "Virtual patch tripped on header '" + target + "'. User input was '" + value + "' and legal pattern was '" + valid.pattern() + "': " + message);
						return new DefaultAction();
					}
				}
			}

		}

	}

	public String getVariable() {
		return variable;
	}

	public void setVariable(String variable) {
		this.variable = variable;
	}

	public PatternEntity getValid() {
		return valid;
	}

	public void setValid(PatternEntity valid) {
		this.valid = valid;
	}

	public String getMessage() {
		return message;
	}

	public void setMessage(String message) {
		this.message = message;
	}

}
