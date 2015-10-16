/**
 * 
 */
package com.wolterskluwer.springsecurity.security;

import java.util.List;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;

/**
 * Extends User with a salt property.
 * 
 * @author Angelo Cammarota
 */

@SuppressWarnings("serial")
public class SaltedUser extends User {
	private String salt;
	private String passwordFormat;
	private String lawfirm;

	public SaltedUser(String username, String lawfirm, String password, boolean enabled,
			boolean accountNonExpired, boolean credentialsNonExpired,
			boolean accountNonLocked, List<GrantedAuthority> authorities, String salt, String passwordFormat) {
		super(username, password, enabled, accountNonExpired, credentialsNonExpired,
				accountNonLocked, authorities);
		this.salt = salt;
		this.passwordFormat=passwordFormat;
		this.lawfirm=lawfirm;
	}

	public String getSalt() {
		return salt;
	}

	public void setSalt(String salt) {
		this.salt = salt;
	}

	public String getPasswordFormat() {
		return passwordFormat;
	}

	public void setPasswordFormat(String passwordFormat) {
		this.passwordFormat = passwordFormat;
	}

	public String getLawfirm() {
		return lawfirm;
	}

	public void setLawfirm(String lawfirm) {
		this.lawfirm = lawfirm;
	}
}
