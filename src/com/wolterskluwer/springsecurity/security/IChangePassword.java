package com.wolterskluwer.springsecurity.security;

import org.springframework.security.core.userdetails.UserDetailsService;

/**
 * Describes a class that allows changing of a user's password.
 * 
 * @author Angelo Cammarota
 */
public interface IChangePassword extends UserDetailsService {

	/**
	 * Changes the user's password. Note that a secure implementation would require
	 * the user to supply their existing password prior to changing it.
	 * 
	 * @param username the username
	 * @param lawfirm the username
	 * @param password the new password
	 */
	void changePassword(String username, String lawfirm, String password);

	void changePassword(String username, String password);

}