package org.owasp.esapi.waf.persistence;

import org.owasp.esapi.waf.rules.AddHTTPOnlyFlagRule;

import br.gov.frameworkdemoiselle.stereotype.PersistenceController;
import br.gov.frameworkdemoiselle.template.JPACrud;

@PersistenceController
public class AddHTTPOnlyFlagRuleDAO extends JPACrud<AddHTTPOnlyFlagRule, String> {
	
	private static final long serialVersionUID = 1L;
	
}
