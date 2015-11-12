package org.owasp.esapi.waf.persistence;

import org.owasp.esapi.waf.rules.RestrictContentTypeRule;

import br.gov.frameworkdemoiselle.stereotype.PersistenceController;
import br.gov.frameworkdemoiselle.template.JPACrud;

@PersistenceController
public class RestrictContentTypeRuleDAO extends JPACrud<RestrictContentTypeRule, String> {
	
	private static final long serialVersionUID = 1L;
	
}