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
public abstract class RuleWithUrlPath extends Rule {

	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	
	@OneToOne (targetEntity=UrlPath.class, cascade={CascadeType.ALL}, orphanRemoval=true)
	@JoinColumn(name = "fk_id_rule", referencedColumnName="id") 
	private UrlPath path;
	
	public RuleWithUrlPath(){
		path = new UrlPath();
	}
	
	public RuleWithUrlPath(String url){
		this.path = new UrlPath(url);
	}
	
	public RuleWithUrlPath(Pattern pattern){
		this.path = new UrlPath(pattern);
	}
	
	public UrlPath getPath() {
		return path;
	}

	public void setPath(UrlPath path) {
		this.path = path;
	}

}
