package com.fams.baseshiro.config.shiro;

import org.apache.shiro.subject.Subject;
import org.apache.shiro.web.filter.AccessControlFilter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;

/**
 * @author gq
 */
public class ResourcesControlFilter extends AccessControlFilter {

	private static final Logger log = LoggerFactory.getLogger(ResourcesControlFilter.class);

	/**
	 * 验证是否登陆和是都有权限
	 * @param request
	 * @param resopnse
	 * @param arg2
	 * @return
	 * @throws Exception
	 */
	@Override
	protected boolean isAccessAllowed(ServletRequest request, ServletResponse resopnse, Object arg2)
			throws Exception {

		Subject subject = getSubject(request, resopnse);
		String url = getPathWithinApplication(request);
		HttpServletRequest req = (HttpServletRequest) request;
		boolean permittedFlag = subject.isPermitted(url+"."+req.getMethod());
		log.info("ResourcesControlFilter check >>> [" + permittedFlag + "] >>>" + req.getMethod()+":"+url);
		return permittedFlag;
	}

	/**
	 * 拒绝访问时调用
	 * @param request
	 * @param response
	 * @return
	 * @throws Exception
	 */
	@Override
	protected boolean onAccessDenied(ServletRequest request, ServletResponse response) throws Exception {

        Subject subject = getSubject(request, response);
        if (subject.getPrincipal() == null) {
			log.info("Access Denied >>> 未登录，重定向到登录页面");
			saveRequestAndRedirectToLogin(request, response);
		} else {
			log.info("Access Denied >>> 已登录，未授权，重定向到未授权页面");
        }
        return false;
	}
}
