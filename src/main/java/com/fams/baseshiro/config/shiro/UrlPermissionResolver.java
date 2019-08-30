package com.fams.baseshiro.config.shiro;

import org.apache.shiro.authz.Permission;
import org.apache.shiro.authz.permission.PermissionResolver;
import org.apache.shiro.authz.permission.WildcardPermission;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @author gq
 */
public class UrlPermissionResolver implements PermissionResolver {

	private static final Logger log = LoggerFactory.getLogger(UrlPermissionResolver.class);
	@Override
	public Permission resolvePermission(String permissionString) {

		String start = "/";
		if(permissionString.startsWith(start)){
			return new UrlPermission(permissionString);
		}
		return new WildcardPermission(permissionString);
	}

}
