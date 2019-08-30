package com.fams.baseshiro.config.shiro;

import com.fams.baseshiro.config.redis.RedisManager;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.ExcessiveAttemptsException;
import org.apache.shiro.authc.credential.HashedCredentialsMatcher;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;

import javax.annotation.Resource;
import java.util.concurrent.atomic.AtomicInteger;

/**
 *
 * @author gq
 * @date 2019/4/23
 */
public class RetryLimitHashedCredentialsMatcher extends HashedCredentialsMatcher {

    private static final Logger logger = LoggerFactory.getLogger(RetryLimitHashedCredentialsMatcher.class);

    public static final String DEFAULT_RETRYLIMIT_CACHE_KEY_PREFIX = "shiro:cache:retrylimit:";
    private String keyPrefix = DEFAULT_RETRYLIMIT_CACHE_KEY_PREFIX;

    @Autowired
    private RedisManager redisManager;

    public void setRedisManager(RedisManager redisManager) {
        this.redisManager = redisManager;
    }

    private String getRedisKickoutKey(String username) {
        return this.keyPrefix + username;
    }

    @Override
    public boolean doCredentialsMatch(AuthenticationToken token, AuthenticationInfo info) {
        //获取用户名
        String userCode = (String)token.getPrincipal();
        //获取用户登录次数

        AtomicInteger retryCount = (AtomicInteger) redisManager.get(getRedisKickoutKey(userCode));
        if (retryCount == null) {
            //如果用户没有登陆过,登陆次数加1 并放入缓存
            retryCount = new AtomicInteger(0);
        }

        int sum = 5;
        if (retryCount.incrementAndGet() > sum) {
            logger.info("锁定用户" + getRedisKickoutKey(userCode));
            //抛出用户锁定异常
            throw new ExcessiveAttemptsException();
        }
        //判断用户账号和密码是否正确
        boolean matches = super.doCredentialsMatch(token, info);
        if (matches) {
            //如果正确,从缓存中将用户登录计数 清除
            redisManager.del(getRedisKickoutKey(userCode));
        }else{
            redisManager.set(getRedisKickoutKey(userCode), retryCount);
            //失效时间300秒
            redisManager.expire(getRedisKickoutKey(userCode),300);
        }
        return matches;
    }
}
