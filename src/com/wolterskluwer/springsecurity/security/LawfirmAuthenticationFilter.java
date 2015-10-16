package com.wolterskluwer.springsecurity.security;

import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.TextEscapeUtils;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
/**
 * 
 * @author Angelo Cammarota
 * 
 */

public class LawfirmAuthenticationFilter extends UsernamePasswordAuthenticationFilter{
     
    public LawfirmAuthenticationFilter() {
        super();
    }
 
    public static final String SPRING_SECURITY_FORM_DOMAIN_KEY = "j_lawfirm";
 
    private String lawfirmParameter = SPRING_SECURITY_FORM_DOMAIN_KEY;
     
    private String alwaysUseDefaultTargetUrl;
 
    private String authenticationFailureUrl;
     
    private String defaultTargetUrl;
     
    private String loginPage;
 
    public String getAlwaysUseDefaultTargetUrl() {
        return alwaysUseDefaultTargetUrl;
    }
 
    public void setAlwaysUseDefaultTargetUrl(String alwaysUseDefaultTargetUrl) {
        this.alwaysUseDefaultTargetUrl = alwaysUseDefaultTargetUrl;
    }
 
    public String getAuthenticationFailureUrl() {
        return authenticationFailureUrl;
    }
 
    public void setAuthenticationFailureUrl(String authenticationFailureUrl) {
        this.authenticationFailureUrl = authenticationFailureUrl;
    }
 
    public String getDefaultTargetUrl() {
        return defaultTargetUrl;
    }
 
    public void setDefaultTargetUrl(String defaultTargetUrl) {
        this.defaultTargetUrl = defaultTargetUrl;
    }
 
    public String getLoginPage() {
        return loginPage;
    }
 
    public void setLoginPage(String loginPage) {
        this.loginPage = loginPage;
    }
     
      public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
            if (!request.getMethod().equals("POST")) {
                throw new AuthenticationServiceException("Authentication method not supported: " + request.getMethod());
            }
 
            String username = obtainUsername(request);
            String password = obtainPassword(request);
            String lawfirm = obtainLawfirm(request);
             
            if (username == null) {
                username = "";
            }
 
            if (password == null) {
                password = "";
            }
 
            if(lawfirm == null){
            	lawfirm = "";
            }
            username = username.trim();
 
            LawfirmAuthenticationToken authRequest = new LawfirmAuthenticationToken(username,password,lawfirm);
 
            // Place the last username attempted into HttpSession for views
            HttpSession session = request.getSession(false);
 
            if (session != null || getAllowSessionCreation()) {
                request.getSession().setAttribute(SPRING_SECURITY_LAST_USERNAME_KEY, TextEscapeUtils.escapeEntities(username));
            }
 
            // Allow subclasses to set the "details" property
            setDetails(request, authRequest);
 
            Authentication authentication = this.getAuthenticationManager().authenticate(authRequest);
          
            if(!(authentication instanceof LawfirmAuthenticationToken))
                throw new RuntimeException("Undesirable toke type");
             
            return authentication;
        }
 
        protected String obtainLawfirm(HttpServletRequest request) {
            return request.getParameter(lawfirmParameter);
        }
}