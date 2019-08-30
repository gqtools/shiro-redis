package com.fams.baseshiro.config.shiro;

import org.apache.shiro.authz.Permission;
import org.apache.shiro.util.AntPathMatcher;
import org.apache.shiro.util.PatternMatcher;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.Serializable;

/**
 * @author gq
 */
public class UrlPermission implements Permission, Serializable {

	private static final Logger log = LoggerFactory.getLogger(UrlPermission.class);

	private String url;

	public String getUrl() {
		return url;
	}

	public void setUrl(String url) {
		this.url = url;
	}

	public UrlPermission(){};
	public UrlPermission(String url){
		this.url = url;
	}
	
	@Override
	public boolean implies(Permission p) {

		if(!(p instanceof UrlPermission)) {
			return false;
		}

		UrlPermission currentUp = (UrlPermission)p;
		PatternMatcher pm = new AntPathMatcher();
		boolean matchFlag = pm.matches(this.url, currentUp.getUrl());
		log.info("核对权限 >>> " + this.url+" >>> "+currentUp.getUrl()+" = " + matchFlag);
		return matchFlag;
	}

}
