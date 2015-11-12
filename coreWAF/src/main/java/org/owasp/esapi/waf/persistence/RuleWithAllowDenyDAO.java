package org.owasp.esapi.waf.persistence;

import org.owasp.esapi.waf.rules.support.RuleWithAllowDeny;

import br.gov.frameworkdemoiselle.stereotype.PersistenceController;
import br.gov.frameworkdemoiselle.template.JPACrud;

@PersistenceController
public class RuleWithAllowDenyDAO extends JPACrud<RuleWithAllowDeny, String> {
	
	private static final long serialVersionUID = 1L;
	
}
