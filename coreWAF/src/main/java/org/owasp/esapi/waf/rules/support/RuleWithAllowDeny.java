package org.owasp.esapi.waf.rules.support;

import java.util.regex.Pattern;

import javax.persistence.CascadeType;
import javax.persistence.Entity;
import javax.persistence.Inheritance;
import javax.persistence.InheritanceType;
import javax.persistence.JoinColumn;
import javax.persistence.OneToOne;

import org.owasp.esapi.waf.rules.Rule;


@Entity
@Inheritance(strategy=InheritanceType.SINGLE_TABLE)
public abstract class RuleWithAllowDeny extends Rule {

	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;

	@OneToOne (targetEntity=PatternEntity.class, cascade={CascadeType.ALL}, orphanRemoval=true)
	@JoinColumn(name = "fk_id_allow", referencedColumnName="id")
	private PatternEntity allow;
	
	@OneToOne (targetEntity=PatternEntity.class, cascade={CascadeType.ALL}, orphanRemoval=true)
	@JoinColumn(name = "fk_id_deny", referencedColumnName="id")
	private PatternEntity deny;
	
	public RuleWithAllowDeny(){
		this.allow = new PatternEntity();
		this.deny = new PatternEntity();
	}
	
	public RuleWithAllowDeny(Pattern allow, Pattern deny){
		if (allow != null)
			this.setAllow(new PatternEntity(allow));
		else this.setAllow(new PatternEntity());
		
		if (deny != null)
			this.setDeny(new PatternEntity(deny));
		else this.setDeny(new PatternEntity());
	}

	public PatternEntity getAllow() {
		return allow;
	}

	public void setAllow(PatternEntity allow) {
		this.allow = allow;
	}

	public PatternEntity getDeny() {
		return deny;
	}

	public void setDeny(PatternEntity deny) {
		this.deny = deny;
	}
}

