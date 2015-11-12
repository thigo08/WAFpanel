package org.owasp.esapi.waf.rules.support;

import java.util.regex.Pattern;

import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;
import javax.persistence.Inheritance;
import javax.persistence.InheritanceType;
import javax.persistence.Transient;

@Entity
@Inheritance(strategy=InheritanceType.SINGLE_TABLE)
public class PatternEntity {
	@Id
	@GeneratedValue
	private Long id;
	
	private String regex;
	
	@Transient
	protected Pattern pattern;

	public PatternEntity(){
		this.pattern = null;
	}
	
	public PatternEntity(String regex) {
		this.setRegex(regex);
		this.pattern = Pattern.compile(regex);
	}
	
	public PatternEntity (Pattern pattern) {
		this.setRegex(pattern.pattern());
		this.pattern = pattern;
	}
	
	public Pattern getPattern(){
		if (regex !=null && pattern == null)
			pattern = Pattern.compile(getRegex());
		return pattern;
	}
	
	public Long getId() {
		return id;
	}

	public void setId(Long id) {
		this.id = id;
	}
	
	public boolean matches (String param){
		if (regex != null)
			return getPattern().matcher(param).matches();
		else return false;
	}

	public String getRegex() {
		return regex;
	}

	public void setRegex(String regex) {
		this.regex = regex;
	}
	
	public String pattern(){
		Pattern p = getPattern();
		if (p != null)
			return getPattern().pattern();
		else return "";
	}
}

