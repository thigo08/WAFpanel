package org.owasp.esapi.waf.persistence;

import org.owasp.esapi.waf.rules.BeanShellRule;

import br.gov.frameworkdemoiselle.stereotype.PersistenceController;
import br.gov.frameworkdemoiselle.template.JPACrud;

@PersistenceController
public class BeanShellRuleDAO extends JPACrud<BeanShellRule, String> {
	
	private static final long serialVersionUID = 1L;
	
}