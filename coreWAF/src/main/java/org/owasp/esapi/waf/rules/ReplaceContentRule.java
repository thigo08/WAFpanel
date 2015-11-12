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

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.persistence.Entity;
import javax.persistence.OneToOne;
import javax.persistence.Transient;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.owasp.esapi.Logger;
import org.owasp.esapi.waf.actions.Action;
import org.owasp.esapi.waf.actions.DoNothingAction;
import org.owasp.esapi.waf.internal.InterceptingHTTPServletResponse;
import org.owasp.esapi.waf.rules.support.PatternEntity;
import org.owasp.esapi.waf.rules.support.RuleWithUrlPath;

/**
 * This is the Rule subclass executed for &lt;dynamic-insertion&gt; rules.
 * @author Arshan Dabirsiaghi
 *
 */
@Entity
public class ReplaceContentRule extends RuleWithUrlPath {
	
	@Transient
	private static final long serialVersionUID = 1L;

	@OneToOne
	private PatternEntity pattern;
	
	private String replacement;
	
	@OneToOne
	private PatternEntity contentType;
	
	public ReplaceContentRule(){
		super();
		pattern = new PatternEntity();
		contentType = new PatternEntity();
	}
	
	public ReplaceContentRule(String id, Pattern pattern, String replacement, Pattern contentType, Pattern path) {
		super(path);
		this.pattern = new PatternEntity(pattern);
		this.replacement = replacement;
		this.contentType = new PatternEntity(contentType);
		setId(id);
	}

	/*
	 * Use regular expressions with capturing parentheses to perform replacement.
	 */

	public Action check(HttpServletRequest request,
			InterceptingHTTPServletResponse response, 
			HttpServletResponse httpResponse) {

		/*
		 * First early fail: if the URI doesn't match the paths we're interested in.
		 */
		String uri = request.getRequestURI();
		if ( getPath() != null && ! getPath().matches(uri) ) {
			return new DoNothingAction();
		}
		
		/*
		 * Second early fail: if the content type is one we'd like to search for output patterns.
		 */

		if ( contentType != null ) {
			if ( response.getContentType() != null && ! contentType.matches(response.getContentType()) ) {
				return new DoNothingAction();
			}
		}

		byte[] bytes = null;

		try {
			bytes = response.getInterceptingServletOutputStream().getResponseBytes();
		} catch (IOException ioe) {
			log(request,"Error matching pattern '" + pattern.pattern() + "', IOException encountered (possibly too large?): " + ioe.getMessage() + " (in response to URL: '" + request.getRequestURL() + "')");
			return new DoNothingAction(); // yes this is a fail open!
		}

		
		try {

			String s = new String(bytes,response.getCharacterEncoding());

			Matcher m = pattern.getPattern().matcher(s);
			String canary = m.replaceAll(replacement);
			
			try {
				
				if ( ! s.equals(canary) ) {
					response.getInterceptingServletOutputStream().setResponseBytes(canary.getBytes(response.getCharacterEncoding()));
					logger.debug(Logger.SECURITY_SUCCESS, "Successfully replaced pattern '" + pattern.pattern() + "' on response to URL '" + request.getRequestURL() + "'");
				}
				
			} catch (IOException ioe) {
				logger.error(Logger.SECURITY_FAILURE, "Failed to replace pattern '" + pattern.pattern() + "' on response to URL '" + request.getRequestURL() + "' due to [" + ioe.getMessage() + "]");
			}

		} catch(UnsupportedEncodingException uee) {
			logger.error(Logger.SECURITY_FAILURE, "Failed to replace pattern '" + pattern.pattern() + "' on response to URL '" + request.getRequestURL() + "' due to [" + uee.getMessage() + "]");
		}

		return new DoNothingAction();
	}

	public PatternEntity getPattern() {
		return pattern;
	}

	public void setPattern(PatternEntity pattern) {
		this.pattern = pattern;
	}

	public String getReplacement() {
		return replacement;
	}

	public void setReplacement(String replacement) {
		this.replacement = replacement;
	}

	public PatternEntity getContentType() {
		return contentType;
	}

	public void setContentType(PatternEntity contentType) {
		this.contentType = contentType;
	}

}
