package org.owasp.esapi.waf.persistence;

import org.owasp.esapi.waf.rules.AddHeaderRule;

import br.gov.frameworkdemoiselle.stereotype.PersistenceController;
import br.gov.frameworkdemoiselle.template.JPACrud;

@PersistenceController
public class AddHeaderRuleDAO extends JPACrud<AddHeaderRule, String> {
	
	private static final long serialVersionUID = 1L;
}
