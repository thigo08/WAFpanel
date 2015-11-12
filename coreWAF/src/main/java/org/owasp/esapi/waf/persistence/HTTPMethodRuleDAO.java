package org.owasp.esapi.waf.persistence;

import org.owasp.esapi.waf.rules.HTTPMethodRule;

import br.gov.frameworkdemoiselle.stereotype.PersistenceController;
import br.gov.frameworkdemoiselle.template.JPACrud;

@PersistenceController
public class HTTPMethodRuleDAO extends JPACrud<HTTPMethodRule, String> {
	
	private static final long serialVersionUID = 1L;
	
}