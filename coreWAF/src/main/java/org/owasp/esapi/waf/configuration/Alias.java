package org.owasp.esapi.waf.configuration;

import java.util.regex.Pattern;

import javax.persistence.Column;
import javax.persistence.Entity;

import org.owasp.esapi.waf.rules.support.UrlPath;

@Entity
public class Alias extends UrlPath{
	
	@Column(unique=true)
	private String name;
	
	public Alias(){
		super();
	}
	
	public Alias(String name, String url){
		super (url);
		setName(name);
	}
	
	public Alias(String name, Pattern pattern){
		super (pattern);
		setName(name);
	}

	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
	}
}
