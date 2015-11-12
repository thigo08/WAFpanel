package org.owasp.esapi.waf.business;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.owasp.esapi.waf.configuration.AppGuardianConfiguration;
import org.owasp.esapi.waf.rules.AddHTTPOnlyFlagRule;
import org.owasp.esapi.waf.rules.AddHeaderRule;
import org.owasp.esapi.waf.rules.AddSecureFlagRule;
import org.owasp.esapi.waf.rules.AuthenticatedRule;
import org.owasp.esapi.waf.rules.BeanShellRule;
import org.owasp.esapi.waf.rules.DetectOutboundContentRule;
import org.owasp.esapi.waf.rules.EnforceHTTPSRule;
import org.owasp.esapi.waf.rules.HTTPMethodRule;
import org.owasp.esapi.waf.rules.IPRule;
import org.owasp.esapi.waf.rules.MustMatchRule;
import org.owasp.esapi.waf.rules.PathExtensionRule;
import org.owasp.esapi.waf.rules.ReplaceContentRule;
import org.owasp.esapi.waf.rules.RestrictContentTypeRule;
import org.owasp.esapi.waf.rules.RestrictUserAgentRule;
import org.owasp.esapi.waf.rules.Rule;
import org.owasp.esapi.waf.rules.SimpleVirtualPatchRule;

import br.gov.frameworkdemoiselle.template.Crud;
import br.gov.frameworkdemoiselle.template.DelegateCrud;
import br.gov.frameworkdemoiselle.transaction.Transactional;
import br.gov.frameworkdemoiselle.util.Beans;

public class DelegateCrudAppGuardianHelper<T, I, C extends Crud<T, I>> extends DelegateCrud<T, I, C> {

	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;

	private AppGuardianConfigurationBC appGuardianConfigurationBC = Beans.getReference(AppGuardianConfigurationBC.class);

	private AppGuardianConfiguration config = appGuardianConfigurationBC.loadSingletonInstance();
	
	public DelegateCrudAppGuardianHelper (){
		
	}

	@Override
	@Transactional	
	public T insert(final T bean) {
		//Rule rule = (Rule) bean; 
		Rule rule = (Rule) super.insert(bean);
		this.getListByRuleType(bean).add(rule);
//
		appGuardianConfigurationBC.update(config);

		return bean;
	}

	@Transactional
	public void delete(final I id) {
		T deletedRule = super.load(id);

		this.getListByRuleType(deletedRule).remove(deletedRule);

		super.delete(id);

		appGuardianConfigurationBC.update(config);
	}

	private static Set<Class> afterBodyRuleSet = new HashSet<Class>();
	private static Set<Class> beforeBodyRuleSet = new HashSet<Class>();
	private static Set<Class> beforeResponseRuleSet = new HashSet<Class>();
	private static Set<Class> cookieRuleSet = new HashSet<Class>();

	static {
		afterBodyRuleSet.add(AuthenticatedRule.class);
		afterBodyRuleSet.add(MustMatchRule.class);
		afterBodyRuleSet.add(SimpleVirtualPatchRule.class);

		beforeBodyRuleSet.add(BeanShellRule.class);
		beforeBodyRuleSet.add(EnforceHTTPSRule.class);
		beforeBodyRuleSet.add(HTTPMethodRule.class);
		beforeBodyRuleSet.add(IPRule.class);
		beforeBodyRuleSet.add(PathExtensionRule.class);
		beforeBodyRuleSet.add(RestrictContentTypeRule.class);
		beforeBodyRuleSet.add(RestrictUserAgentRule.class);

		beforeResponseRuleSet.add(AddHeaderRule.class);
		beforeResponseRuleSet.add(DetectOutboundContentRule.class);
		beforeResponseRuleSet.add(ReplaceContentRule.class);

		cookieRuleSet.add(AddHTTPOnlyFlagRule.class);
		cookieRuleSet.add(AddSecureFlagRule.class);

	}

	public List<Rule> getListByRuleType(T ruleType) {
		Rule rule = (Rule) ruleType;

		if (afterBodyRuleSet.contains(rule.getClass()))
			return config.getAfterBodyRules();
		if (beforeBodyRuleSet.contains(rule.getClass()))
			return config.getBeforeBodyRules();
		if (beforeResponseRuleSet.contains(rule.getClass()))
			return config.getBeforeResponseRules();
		if (cookieRuleSet.contains(rule.getClass()))
			return config.getCookieRules();

		return new ArrayList<Rule>();

		// if (rule instanceof AddHeaderRule)
		// return config.getBeforeResponseRules();
		//
		// if (rule instanceof AddHTTPOnlyFlagRule)
		// return config.getCookieRules();
		//
		// if (rule instanceof AddSecureFlagRule)
		// return config.getCookieRules();
		//
		// if (rule instanceof AuthenticatedRule)
		// return config.getAfterBodyRules();
		//
		// if (rule instanceof BeanShellRule)
		// return config.getBeforeBodyRules();
		//
		// if (rule instanceof DetectOutboundContentRule)
		// return config.getBeforeResponseRules();
		//
		// if (rule instanceof EnforceHTTPSRule)
		// return config.getBeforeBodyRules();
		//
		// if (rule instanceof HTTPMethodRule)
		// return config.getBeforeBodyRules();
		//
		// if (rule instanceof IPRule)
		// return config.getBeforeBodyRules();
		//
		// if (rule instanceof MustMatchRule)
		// return config.getAfterBodyRules();
		//
		// if (rule instanceof PathExtensionRule)
		// return config.getBeforeBodyRules();
		//
		// if (rule instanceof ReplaceContentRule)
		// return config.getBeforeResponseRules();
		//
		// if (rule instanceof RestrictContentTypeRule)
		// return config.getBeforeBodyRules();
		//
		// if (rule instanceof RestrictUserAgentRule)
		// return config.getBeforeBodyRules();
		//
		// if (rule instanceof SimpleVirtualPatchRule)
		// return config.getAfterBodyRules();
		//
		// return null;
	}

}
