package org.owasp.esapi.waf.persistence;

import org.owasp.esapi.waf.rules.support.RuleWithPatterns;

import br.gov.frameworkdemoiselle.stereotype.PersistenceController;
import br.gov.frameworkdemoiselle.template.JPACrud;

@PersistenceController
public class RuleWithPatternsDAO extends JPACrud<RuleWithPatterns, String> {
	
	private static final long serialVersionUID = 1L;
	
}
