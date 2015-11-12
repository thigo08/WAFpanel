package org.owasp.esapi.waf.business;


import org.owasp.esapi.waf.persistence.UrlPathDAO;
import org.owasp.esapi.waf.rules.support.UrlPath;

import br.gov.frameworkdemoiselle.stereotype.BusinessController;
import br.gov.frameworkdemoiselle.template.DelegateCrud;

@BusinessController
public class UrlPathBC extends DelegateCrud<UrlPath, Long, UrlPathDAO> {

	private static final long serialVersionUID = 1L;


}
