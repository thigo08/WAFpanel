package org.owasp.esapi.waf.persistence;

import org.owasp.esapi.waf.rules.support.RuleWithExceptions;

import br.gov.frameworkdemoiselle.stereotype.PersistenceController;
import br.gov.frameworkdemoiselle.template.JPACrud;

@PersistenceController
public class RuleWithExceptionsDAO extends JPACrud<RuleWithExceptions, String> {
	
	private static final long serialVersionUID = 1L;
	
}
