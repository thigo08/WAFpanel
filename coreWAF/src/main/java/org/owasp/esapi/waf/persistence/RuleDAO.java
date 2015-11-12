package org.owasp.esapi.waf.persistence;

import org.owasp.esapi.waf.rules.Rule;

import br.gov.frameworkdemoiselle.stereotype.PersistenceController;
import br.gov.frameworkdemoiselle.template.JPACrud;

@PersistenceController
public class RuleDAO extends JPACrud<Rule, String> {
	
	private static final long serialVersionUID = 1L;
	
}
