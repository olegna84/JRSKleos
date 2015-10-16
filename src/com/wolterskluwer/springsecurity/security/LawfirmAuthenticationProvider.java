package com.wolterskluwer.springsecurity.security;

import org.springframework.dao.DataAccessException;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.util.Assert;

/**
 * 
 * @author Angelo Cammarota
 * 
 */

public class LawfirmAuthenticationProvider extends DaoAuthenticationProvider {
	@Override
	public Authentication authenticate(Authentication originalAuthentication) throws AuthenticationException {
		Assert.isInstanceOf(LawfirmAuthenticationToken.class, originalAuthentication,
				messages.getMessage("AbstractUserDetailsAuthenticationProvider.onlySupports",
						"Only LawfirmAuthenticationToken is supported"));

		LawfirmAuthenticationToken authentication = (LawfirmAuthenticationToken)originalAuthentication;

		// Determine username
		String username = (authentication.getPrincipal() == null) ? "NONE_PROVIDED" : authentication.getName();

		boolean cacheWasUsed = true;

		SaltedUser saltedUser = null;//this.getUserCache().getUserFromCache(username);

		//        if (user == null) {
		cacheWasUsed = false;

		try {
			saltedUser =  retrieveSaltedUser(username, authentication);
		} catch (UsernameNotFoundException notFound) {
			if (hideUserNotFoundExceptions) {
				throw new BadCredentialsException(messages.getMessage(
						"AbstractUserDetailsAuthenticationProvider.badCredentials", "Bad credentials"));
			} else {
				throw notFound;
			}
		}

		Assert.notNull(saltedUser, "retrieveUser returned null - a violation of the interface contract");
		//        }

		try {
			this.getPreAuthenticationChecks().check(saltedUser);
			additionalAuthenticationChecks(saltedUser, (UsernamePasswordAuthenticationToken) authentication);
		} catch (AuthenticationException exception) {
			if (cacheWasUsed) {
				// There was a problem, so try again after checking
				// we're using latest data (i.e. not from the cache)
				cacheWasUsed = false;
				saltedUser =  retrieveSaltedUser(username, authentication);
				this.getPreAuthenticationChecks().check(saltedUser);
				additionalAuthenticationChecks(saltedUser, (UsernamePasswordAuthenticationToken) authentication);
			} else {
				throw exception;
			}
		}
		this.getPostAuthenticationChecks().check(saltedUser);

		if (!cacheWasUsed) {
			this.getUserCache().putUserInCache(saltedUser);
		}

		Object principalToReturn = saltedUser;

		if (this.isForcePrincipalAsString()) {
			principalToReturn = saltedUser.getUsername();
		}

		return createSuccessAuthentication2(principalToReturn, authentication, saltedUser);
	}

	protected Authentication createSuccessAuthentication2(Object principal, Authentication authentication,
			SaltedUser user) {
		// Ensure we return the original credentials the user supplied,
		// so subsequent attempts are successful even with encoded passwords.
		// Also ensure we return the original getDetails(), so that future
		// authentication events after cache expiry contain the details
		LawfirmAuthenticationToken result =   new LawfirmAuthenticationToken(principal,
				authentication.getCredentials(), user.getAuthorities());
		result.setDetails(authentication.getDetails());
		result.setLawfirmName(user.getLawfirm());
		return result;
	}

	protected final SaltedUser retrieveSaltedUser(String username, LawfirmAuthenticationToken authentication)
			throws AuthenticationException {
		Assert.isInstanceOf(KleosUserDetailsManager.class, this.getUserDetailsService());

		SaltedUser loadedLawfirmUser = null;

		try {
			if(this.getUserDetailsService() instanceof KleosUserDetailsManager){
				KleosUserDetailsManager lawfirmUserDetailsManager = (KleosUserDetailsManager)this.getUserDetailsService();             
				loadedLawfirmUser = lawfirmUserDetailsManager.loadLawfirmUserByUserName(username,authentication.getLawfirmName());
			}

		}
		catch (DataAccessException repositoryProblem) {
			throw new AuthenticationServiceException(repositoryProblem.getMessage(), repositoryProblem);
		}

		if (loadedLawfirmUser == null) {
			throw new AuthenticationServiceException(
					"UserDetailsService returned null, which is an interface contract violation");
		}
		return loadedLawfirmUser;
	}
}