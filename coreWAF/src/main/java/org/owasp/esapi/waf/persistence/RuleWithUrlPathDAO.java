package org.owasp.esapi.waf.persistence;

import org.owasp.esapi.waf.rules.support.RuleWithUrlPath;

import br.gov.frameworkdemoiselle.stereotype.PersistenceController;
import br.gov.frameworkdemoiselle.template.JPACrud;

@PersistenceController
public class RuleWithUrlPathDAO extends JPACrud<RuleWithUrlPath, String> {
	
	private static final long serialVersionUID = 1L;
	
}
