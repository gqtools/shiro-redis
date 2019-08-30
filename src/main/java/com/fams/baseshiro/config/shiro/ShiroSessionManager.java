package com.fams.baseshiro.config.shiro;

import org.apache.commons.lang3.StringUtils;
import org.apache.shiro.session.Session;
import org.apache.shiro.session.UnknownSessionException;
import org.apache.shiro.session.mgt.SessionKey;
import org.apache.shiro.web.servlet.ShiroHttpServletRequest;
import org.apache.shiro.web.session.mgt.DefaultWebSessionManager;
import org.apache.shiro.web.session.mgt.WebSessionKey;
import org.apache.shiro.web.util.WebUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import java.io.Serializable;

/**
 * @author: gq
 * @date: 2018/6/23
 * @description: 解决单次请求需要多次访问redis
 */
public class ShiroSessionManager extends DefaultWebSessionManager {

    private static Logger logger = LoggerFactory.getLogger(DefaultWebSessionManager.class);

    public ShiroSessionManager() {
        super();
    }

    @Override
    protected Serializable getSessionId(ServletRequest request, ServletResponse response) {

        String id = WebUtils.toHttp(request).getHeader("FASSESSIONID");
        HttpServletRequest request1 = (HttpServletRequest) request;
        Cookie[] cookies = request1.getCookies();
        if(cookies != null && cookies.length > 0){
            for (Cookie cookie :cookies) {
                if("FASSESSIONID".equals(cookie.getName())){
                    id = cookie.getValue();
                }
            }
        }

        String result = "null";
        if (!StringUtils.isEmpty(id) && !result.equals(id)) {
            request.setAttribute(ShiroHttpServletRequest.REFERENCED_SESSION_ID_SOURCE, "Stateless request");
            request.setAttribute(ShiroHttpServletRequest.REFERENCED_SESSION_ID, id);
            request.setAttribute(ShiroHttpServletRequest.REFERENCED_SESSION_ID_IS_VALID, Boolean.TRUE);
            return id;
        } else {
            //否则按默认规则从cookie取sessionId
            return super.getSessionId(request, response);
        }
    }

    /**
     * 获取session
     * 优化单次请求需要多次访问redis的问题
     * @param sessionKey
     * @return
     * @throws UnknownSessionException
     */
    @Override
    protected Session retrieveSession(SessionKey sessionKey) throws UnknownSessionException {
        Serializable sessionId = getSessionId(sessionKey);

        ServletRequest request = null;
        if (sessionKey instanceof WebSessionKey) {
            request = ((WebSessionKey) sessionKey).getServletRequest();
        }

        if (request != null && null != sessionId) {
            Object sessionObj = request.getAttribute(sessionId.toString());
            if (sessionObj != null) {
                logger.debug("read session from request");
                return (Session) sessionObj;
            }
        }

        Session session = null;
        try{
            //当session为空时会抛出UnknownSessionException异常
            session = super.retrieveSession(sessionKey);
        }catch (UnknownSessionException e){
            return null;
        }

        if (request != null && null != sessionId) {
            request.setAttribute(sessionId.toString(), session);
        }

        return session;
    }

}
