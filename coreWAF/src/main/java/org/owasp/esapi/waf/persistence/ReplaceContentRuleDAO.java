package org.owasp.esapi.waf.persistence;

import org.owasp.esapi.waf.rules.ReplaceContentRule;

import br.gov.frameworkdemoiselle.stereotype.PersistenceController;
import br.gov.frameworkdemoiselle.template.JPACrud;

@PersistenceController
public class ReplaceContentRuleDAO extends JPACrud<ReplaceContentRule, String> {
	
	private static final long serialVersionUID = 1L;
	
}