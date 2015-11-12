package org.owasp.esapi.waf.persistence;

import org.owasp.esapi.waf.rules.RestrictUserAgentRule;

import br.gov.frameworkdemoiselle.stereotype.PersistenceController;
import br.gov.frameworkdemoiselle.template.JPACrud;

@PersistenceController
public class RestrictUserAgentRuleDAO extends JPACrud<RestrictUserAgentRule, String> {
	
	private static final long serialVersionUID = 1L;
	
}	