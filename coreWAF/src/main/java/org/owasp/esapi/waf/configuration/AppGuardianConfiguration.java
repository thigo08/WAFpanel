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
package org.owasp.esapi.waf.configuration;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.regex.Pattern;

import javax.persistence.CascadeType;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;
import javax.persistence.JoinColumn;
import javax.persistence.OneToMany;
import javax.persistence.Transient;

import org.apache.log4j.Level;
import org.owasp.esapi.waf.rules.Rule;

/**
 * This class is the object model of the policy file. Also holds a number of constants
 * used throughout the WAF.
 * 
 * @author Arshan Dabirsiaghi
 *
 */
@Entity
public class AppGuardianConfiguration {

	@Id
	@GeneratedValue
	private Long id;
	
	/*
	 * Fail modes (BLOCK blocks and logs the request, DONT_BLOCK simply logs)
	 */
	@Transient
	public static final int LOG = 0;
	@Transient
	public static final int REDIRECT = 1;
	@Transient
	public static final int BLOCK = 2;

	/*
	 * The operators.
	 */
	@Transient
	public static final int OPERATOR_EQ = 0;
	@Transient
	public static final int OPERATOR_CONTAINS = 1;
	@Transient
	public static final int OPERATOR_IN_LIST = 2;
	@Transient
	public static final int OPERATOR_EXISTS = 3;

	/*
	 * We have static copies of the log settings so that the Rule objects
	 * can access them, because they don't have access to the instance of
	 * the configuration object.
	 */
	@Transient
	public static Level LOG_LEVEL = Level.INFO;	
	@Transient
	public static String LOG_DIRECTORY = "/WEB-INF/logs";

	/*
	 * Logging settings.
	 */
	@Transient
	private Level logLevel = Level.INFO;
	private String logDirectory = "/WEB-INF/logs";

	/*
	 * Default settings.
	 */
	//@Transient
	//public static int DEFAULT_FAIL_ACTION = LOG;
	private int defaultFailAction = LOG;

	// TODO: use UTF-8
	@Transient
	public static String DEFAULT_CHARACTER_ENCODING = "ISO-8859-1";
	@Transient
	public static String DEFAULT_CONTENT_TYPE = "text/html; charset=" + DEFAULT_CHARACTER_ENCODING;

	/*
	 * The JavaScript to redirect users to the default error page. Have
	 * to use this because response.sendRedirect() can't have an arbitrary
	 * response code and that is a requirement.
	 */
	@Transient
	public static final String JAVASCRIPT_TARGET_TOKEN = "##1##";
	@Transient
	public static final String JAVASCRIPT_REDIRECT = "<html><body><script>document.location='" + JAVASCRIPT_TARGET_TOKEN + "';</script></body></html>";

	/*
	 * The aliases declared in the beginning of the config file.
	 */
	//TODO: Resolver como @OneToMany
	@Transient
	private HashMap<String,Alias> aliases;

	/*
	 * Fail response settings.
	 */
	private String defaultErrorPage;
	private int defaultResponseCode;

	private boolean forceHttpOnlyFlagToSession = false;
	private boolean forceSecureFlagToSession = false;

	private String sessionCookieName;
	
	public String getSessionCookieName() {
		return sessionCookieName;
	}

	public void setSessionCookieName(String sessionCookieName) {
		this.sessionCookieName = sessionCookieName;
	}

	/*
	 * The object-level rules encapsulated by the stage in which they are executed.
	 */
	@OneToMany (cascade = CascadeType.ALL, orphanRemoval=true)
	@JoinColumn(name = "ID_BEFORE_BODY_RULES", nullable = true)
	private List<Rule> beforeBodyRules;
	
	@OneToMany (cascade = CascadeType.ALL, orphanRemoval=true)
	@JoinColumn(name = "ID_AFTER_BODY_RULES", nullable = true)
	private List<Rule> afterBodyRules;
	
	@OneToMany (cascade = CascadeType.ALL, orphanRemoval=true)
	@JoinColumn(name = "ID_BEFORE_RESPONSE_RULES", nullable = true)
	private List<Rule> beforeResponseRules;
	
	@OneToMany (cascade = CascadeType.ALL, orphanRemoval=true)
	@JoinColumn(name = "ID_COOKIE_RULES", nullable = true)
	private List<Rule> cookieRules;

	public AppGuardianConfiguration() {
		this.setDefaultFailAction(LOG);
		this.setSessionCookieName("/");
		this.setDefaultResponseCode(400);
		this.setDefaultErrorPage("/");
		beforeBodyRules = new ArrayList<Rule>();
		afterBodyRules = new ArrayList<Rule>();
		beforeResponseRules = new ArrayList<Rule>();
		cookieRules = new ArrayList<Rule>();
		aliases = new HashMap<String,Alias>();
	}

	/*
	 * The following methods are all deprecated because
	 * we use ESAPI logging structures now.
	 */
	@Deprecated
	public Level getLogLevel() {
		return logLevel;
	}
	
	@Deprecated
	public void setLogLevel(Level level) {
		LOG_LEVEL = level;
		this.logLevel = level;
	}
	
	@Deprecated
	public void setLogDirectory(String dir) {
		LOG_DIRECTORY = dir;
		this.logDirectory = dir;
	}
	
	@Deprecated
	public String getLogDirectory() {
		return logDirectory;
	}
	
	public String getDefaultErrorPage() {
		return defaultErrorPage;
	}

	public void setDefaultErrorPage(String defaultErrorPage) {
		this.defaultErrorPage = defaultErrorPage;
	}

	public int getDefaultResponseCode() {
		return defaultResponseCode;
	}

	public void setDefaultResponseCode(int defaultResponseCode) {
		this.defaultResponseCode = defaultResponseCode;
	}

	public void addAlias(String key, Object obj) {
		Alias alias = null;
		if (obj instanceof String)
			alias = new Alias(key, (String)obj);
		if (obj instanceof Pattern)
			alias = new Alias(key, (Pattern)obj);
		aliases.put(key, alias);
	}

	public List<Rule> getBeforeBodyRules() {
		return beforeBodyRules;
	}

	public List<Rule> getAfterBodyRules() {
		return afterBodyRules;
	}

	public List<Rule> getBeforeResponseRules() {
		return beforeResponseRules;
	}

	public List<Rule> getCookieRules() {
		return cookieRules;
	}

	public void addBeforeBodyRule(Rule r) {
		beforeBodyRules.add(r);
	}

	public void addAfterBodyRule(Rule r) {
		afterBodyRules.add(r);
	}

	public void addBeforeResponseRule(Rule r) {
		beforeResponseRules.add(r);
	}

	public void addCookieRule(Rule r) {
		cookieRules.add(r);
	}

	public void setApplyHTTPOnlyFlagToSessionCookie(boolean shouldApply) {
		forceHttpOnlyFlagToSession = shouldApply;
	}

	public void setApplySecureFlagToSessionCookie(boolean shouldApply) {
		forceSecureFlagToSession = shouldApply;
	}
	
	public boolean isUsingHttpOnlyFlagOnSessionCookie() {
		return forceHttpOnlyFlagToSession;
	}

	public boolean isUsingSecureFlagOnSessionCookie() {
		return forceSecureFlagToSession;
	}
	
	public String toString() {
		StringBuilder sb = new StringBuilder( "WAF Configuration\n" );
		sb.append( "Before body rules:\n" );
		for ( Rule rule : beforeBodyRules ) sb.append( "  " + rule.toString() + "\n" );
		sb.append( "After body rules:\n" );
		for ( Rule rule : afterBodyRules ) sb.append( "  " + rule.toString() + "\n" );
		sb.append( "Before response rules:\n" );
		for ( Rule rule : beforeResponseRules ) sb.append( "  " + rule.toString() + "\n" );
		sb.append( "Cookie rules:\n" );
		for ( Rule rule : cookieRules ) sb.append( "  " + rule.toString() + "\n" );
		return sb.toString();
	}

	public Long getId() {
		return id;
	}

	public void setId(Long id) {
		this.id = id;
	}

	public int getDefaultFailAction() {
		return defaultFailAction;
	}

	public void setDefaultFailAction(int defaultFailAction) {
		this.defaultFailAction = defaultFailAction;
	}
}