package org.owasp.esapi.waf.business;


import org.owasp.esapi.waf.persistence.PatternEntityDAO;
import org.owasp.esapi.waf.rules.support.PatternEntity;

import br.gov.frameworkdemoiselle.stereotype.BusinessController;
import br.gov.frameworkdemoiselle.template.DelegateCrud;

@BusinessController
public class PatternEntityBC extends DelegateCrud<PatternEntity, Long, PatternEntityDAO> {

	private static final long serialVersionUID = 1L;


}
