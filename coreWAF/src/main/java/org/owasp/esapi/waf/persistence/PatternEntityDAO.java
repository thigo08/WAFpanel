package org.owasp.esapi.waf.persistence;

import org.owasp.esapi.waf.rules.support.PatternEntity;

import br.gov.frameworkdemoiselle.stereotype.PersistenceController;
import br.gov.frameworkdemoiselle.template.JPACrud;

@PersistenceController
public class PatternEntityDAO extends JPACrud<PatternEntity, Long> {

	private static final long serialVersionUID = 1L;

}
