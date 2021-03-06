package org.owasp.esapi.waf.persistence;

import org.owasp.esapi.waf.rules.MustMatchRule;

import br.gov.frameworkdemoiselle.stereotype.PersistenceController;
import br.gov.frameworkdemoiselle.template.JPACrud;

@PersistenceController
public class MustMatchRuleDAO extends JPACrud<MustMatchRule, String> {
	
	private static final long serialVersionUID = 1L;
	
}