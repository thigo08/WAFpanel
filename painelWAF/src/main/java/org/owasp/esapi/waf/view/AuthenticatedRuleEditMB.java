/*
 Demoiselle Framework
 Copyright (C) 2013 SERPRO
 ============================================================================
 This file is part of Demoiselle Framework.
 Demoiselle Framework is free software; you can redistribute it and/or
 modify it under the terms of the GNU Lesser General Public License version 3
 as published by the Free Software Foundation.
 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.
 You should have received a copy of the GNU Lesser General Public License version 3
 along with this program; if not,  see <http://www.gnu.org/licenses/>
 or write to the Free Software Foundation, Inc., 51 Franklin Street,
 Fifth Floor, Boston, MA  02110-1301, USA.
 ============================================================================
 Este arquivo é parte do Framework Demoiselle.
 O Framework Demoiselle é um software livre; você pode redistribuí-lo e/ou
 modificá-lo dentro dos termos da GNU LGPL versão 3 como publicada pela Fundação
 do Software Livre (FSF).
 Este programa é distribuído na esperança que possa ser útil, mas SEM NENHUMA
 GARANTIA; sem uma garantia implícita de ADEQUAÇÃO a qualquer MERCADO ou
 APLICAÇÃO EM PARTICULAR. Veja a Licença Pública Geral GNU/LGPL em português
 para maiores detalhes.
 Você deve ter recebido uma cópia da GNU LGPL versão 3, sob o título
 "LICENCA.txt", junto com esse programa. Se não, acesse <http://www.gnu.org/licenses/>
 ou escreva para a Fundação do Software Livre (FSF) Inc.,
 51 Franklin St, Fifth Floor, Boston, MA 02111-1301, USA.
 */
package org.owasp.esapi.waf.view;

import javax.faces.model.DataModel;
import javax.faces.model.ListDataModel;
import javax.inject.Inject;

import org.owasp.esapi.waf.business.AuthenticatedRuleBC;
import org.owasp.esapi.waf.rules.AuthenticatedRule;
import org.owasp.esapi.waf.rules.support.UrlPath;

import br.gov.frameworkdemoiselle.annotation.PreviousView;
import br.gov.frameworkdemoiselle.stereotype.ViewController;
import br.gov.frameworkdemoiselle.template.AbstractEditPageBean;
import br.gov.frameworkdemoiselle.transaction.Transactional;

@ViewController
@PreviousView("./authenticatedrule_list.jsf")
public class AuthenticatedRuleEditMB extends AbstractEditPageBean<AuthenticatedRule, String> {

	private static final long serialVersionUID = 1L;
	
	private DataModel<UrlPath> pathexceptions;
	
	@Inject
	private AuthenticatedRuleBC authenticatedRuleBC;
	
	@Override
	@Transactional
	public String delete() {
		this.authenticatedRuleBC.delete(getId());
		return getPreviousView();
	}
	
	@Override
	@Transactional
	public String insert() {		
		this.authenticatedRuleBC.insert(getBean());
		return getPreviousView();
	}
	
	
	@Override
	@Transactional
	public String update() {
		this.authenticatedRuleBC.update(getBean());
		return getPreviousView();
	}
	
	public DataModel<UrlPath> getPathExceptions() {
		if (pathexceptions == null) {
			pathexceptions = new ListDataModel<UrlPath>(getBean().getExceptions());
		}

		return pathexceptions;
	}
	
	public void addPathException() {
		getBean().getExceptions().add(new UrlPath());
	}

	public void deletePathException() {
		getBean().getExceptions().remove(getPathExceptions().getRowData());
	}

	@Override
	protected AuthenticatedRule handleLoad(String id) {
		return this.authenticatedRuleBC.load(id);
	}
		
}