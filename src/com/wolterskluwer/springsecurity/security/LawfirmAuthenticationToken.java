package com.wolterskluwer.springsecurity.security;
 
import java.util.Collection;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
/**
 * 
 * @author Angelo Cammarota
 * 
 */
public class LawfirmAuthenticationToken extends UsernamePasswordAuthenticationToken{
     
    /**
     * default serial version uid
     */
    private static final long serialVersionUID = 1L;
 
     
    private String lawfirmName = null;
     
   
 
    public LawfirmAuthenticationToken(Object principal,Object credentials,Collection<GrantedAuthority> authorities){
        super(principal,credentials,authorities);
    }
     
    public LawfirmAuthenticationToken(String username,String password,String lawfirm){        
        super(username,password);
        this.setLawfirmName(lawfirm);
    }

	public String getLawfirmName() {
		return lawfirmName;
	}

	public void setLawfirmName(String lawfirmName) {
		this.lawfirmName = lawfirmName;
	}
 
     
}