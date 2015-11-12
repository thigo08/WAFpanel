package org.owasp.esapi.waf.rules.support;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

import javax.persistence.CascadeType;
import javax.persistence.Entity;
import javax.persistence.FetchType;
import javax.persistence.Inheritance;
import javax.persistence.InheritanceType;
import javax.persistence.JoinColumn;
import javax.persistence.OneToMany;

@Entity
@Inheritance(strategy=InheritanceType.SINGLE_TABLE)
public abstract class RuleWithExceptions extends RuleWithUrlPath {
	
	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	
	@OneToMany(cascade = CascadeType.ALL, fetch = FetchType.LAZY, orphanRemoval=true)
	@JoinColumn(name = "fk_id_rule")
	private List<UrlPath> exceptions;
	
	public RuleWithExceptions(){
		super ();
	}
	
	public RuleWithExceptions(Pattern pattern) {
		super (pattern);
	}
	
	public RuleWithExceptions(String url) {
		super (url);
	}

	protected void fillExceptionsWithListOfObjects(List<Object> listExceptions){
		for (Object exception : listExceptions){
			if (exception instanceof String){
				getExceptions().add(new UrlPath ((String)exception));
			}
			if (exception instanceof Pattern){
				getExceptions().add(new UrlPath ((Pattern)exception));
			}
		}
	}
	
	public List<UrlPath> getExceptions() {
		if(exceptions == null)
			exceptions = new ArrayList<UrlPath>();
		return exceptions;
	}

	public void setExceptions(List<UrlPath> exceptions) {
		this.exceptions = exceptions;
	}

}
