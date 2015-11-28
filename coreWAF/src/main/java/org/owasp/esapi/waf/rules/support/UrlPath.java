package org.owasp.esapi.waf.rules.support;

import java.util.regex.Pattern;

import javax.persistence.Entity;

@Entity
public class UrlPath extends PatternEntity {
	
	private boolean typeRegex;
	
	public UrlPath (){
		this.setRegex("/");
		this.typeRegex = true;
	}
	
	public UrlPath(Pattern pattern){
		super(pattern);
		this.typeRegex = true;
	}
	
	public UrlPath(String url){
		this.pattern = null;
		this.setUrl(url);
		this.typeRegex = false;
	}
	
	public boolean matches(String uri){
		if (typeRegex){			
			return super.matches(uri);				
		} else {
			return this.getUrl().equals(uri);
		}
	}
		
	public UrlPath (String path, boolean regex){
		this.setUrl(path);
		this.typeRegex = regex;
	}

	public String getUrl() {
		return super.getRegex();
	}

	public void setUrl(String url) {
		super.setRegex(url);
	}

	public boolean isTypeRegex() {
		return typeRegex;
	}

	public void setTypeRegex(boolean typeRegex) {
		this.typeRegex = typeRegex;
	}
}
