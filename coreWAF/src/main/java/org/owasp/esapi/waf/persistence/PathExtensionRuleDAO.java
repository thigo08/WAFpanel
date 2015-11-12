package org.owasp.esapi.waf.persistence;

import org.owasp.esapi.waf.rules.PathExtensionRule;

import br.gov.frameworkdemoiselle.stereotype.PersistenceController;
import br.gov.frameworkdemoiselle.template.JPACrud;

@PersistenceController
public class PathExtensionRuleDAO extends JPACrud<PathExtensionRule, String> {
	
	private static final long serialVersionUID = 1L;
	
}