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

import java.util.Iterator;
import java.util.List;

import javax.inject.Inject;

import org.owasp.esapi.waf.business.AuthenticatedRuleBC;
import org.owasp.esapi.waf.rules.AuthenticatedRule;

import br.gov.frameworkdemoiselle.annotation.NextView;
import br.gov.frameworkdemoiselle.annotation.PreviousView;
import br.gov.frameworkdemoiselle.stereotype.ViewController;
import br.gov.frameworkdemoiselle.template.AbstractListPageBean;
import br.gov.frameworkdemoiselle.transaction.Transactional;

@ViewController
@NextView("./authenticatedrule_edit.jsf")
@PreviousView("./authenticatedrule_list.jsf")
public class AuthenticatedRuleListMB extends AbstractListPageBean<AuthenticatedRule, String> {

	private static final long serialVersionUID = 1L;

	
	@Inject
	private AuthenticatedRuleBC authenticatedRuleBC;
	
//	@Inject
//	private ControleExcecoes controleExcecoes;
//
//   @PostConstruct
//	private final void init() {
//    	for (int i=0;i<10;i++){
//    		System.out.println(i);
//    		if (i == 9) controleExcecoes.chamaExcecao();
//    	}
//		
//	}

	@Override
	protected List<AuthenticatedRule> handleResultList() {
		//throw new TesteException();
		return this.authenticatedRuleBC.findAll();
	}

	@Transactional
	public String deleteSelection() {
		boolean delete;
		for (Iterator<String> iter = getSelection().keySet().iterator(); iter
				.hasNext();) {
			String id = iter.next();
			delete = getSelection().get(id);
			if (delete) {
				authenticatedRuleBC.delete(id);
				iter.remove();
			}
		}
		return getPreviousView();
	}

	

}