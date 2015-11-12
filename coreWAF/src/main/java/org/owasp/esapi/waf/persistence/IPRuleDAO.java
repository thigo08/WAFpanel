package org.owasp.esapi.waf.persistence;

import org.owasp.esapi.waf.rules.IPRule;

import br.gov.frameworkdemoiselle.stereotype.PersistenceController;
import br.gov.frameworkdemoiselle.template.JPACrud;

@PersistenceController
public class IPRuleDAO extends JPACrud<IPRule, String> {
	
	private static final long serialVersionUID = 1L;
	
}