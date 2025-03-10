package com.example.uauth.util;

import com.wf.captcha.SpecCaptcha;
import com.wf.captcha.base.Captcha;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Component;

import java.util.UUID;
import java.util.concurrent.TimeUnit;

/**
 * 验证码工具类
 */
@Component
public class CaptchaUtil {
    
    @Autowired
    private RedisTemplate<String, Object> redisTemplate;
    
    private static final String CAPTCHA_PREFIX = "captcha:";
    
    /**
     * 生成验证码
     * @return 包含验证码信息的对象
     */
    public CaptchaResult generateCaptcha() {
        // 生成验证码
        SpecCaptcha captcha = new SpecCaptcha(130, 48, 5);
        // 设置类型，字母数字混合
        captcha.setCharType(Captcha.TYPE_DEFAULT);
        
        // 生成验证码的值
        String captchaValue = captcha.text().toLowerCase();
        
        // 生成验证码的key
        String captchaKey = UUID.randomUUID().toString();
        
        // 将验证码值存入Redis，2分钟过期
        redisTemplate.opsForValue().set(CAPTCHA_PREFIX + captchaKey, captchaValue, 2, TimeUnit.MINUTES);
        
        // 返回结果
        CaptchaResult result = new CaptchaResult();
        result.setCaptchaKey(captchaKey);
        result.setCaptchaImage(captcha.toBase64());
        return result;
    }
    
    /**
     * 验证验证码
     * @param captchaKey 验证码key
     * @param captchaValue 用户输入的验证码值
     * @return 是否验证成功
     */
    public boolean verifyCaptcha(String captchaKey, String captchaValue) {
        if (captchaKey == null || captchaValue == null) {
            return false;
        }
        
        // 从Redis获取验证码
        String redisCaptcha = (String) redisTemplate.opsForValue().get(CAPTCHA_PREFIX + captchaKey);
        
        // 验证码不存在或已过期
        if (redisCaptcha == null) {
            return false;
        }
        
        // 验证成功后，删除Redis中的验证码
        redisTemplate.delete(CAPTCHA_PREFIX + captchaKey);
        
        // 对比验证码，忽略大小写
        return redisCaptcha.equalsIgnoreCase(captchaValue);
    }
    
    /**
     * 验证码结果类
     */
    public static class CaptchaResult {
        private String captchaKey;
        private String captchaImage;
        
        public String getCaptchaKey() {
            return captchaKey;
        }
        
        public void setCaptchaKey(String captchaKey) {
            this.captchaKey = captchaKey;
        }
        
        public String getCaptchaImage() {
            return captchaImage;
        }
        
        public void setCaptchaImage(String captchaImage) {
            this.captchaImage = captchaImage;
        }
    }
} 