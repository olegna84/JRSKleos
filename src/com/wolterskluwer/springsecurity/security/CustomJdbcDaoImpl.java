package com.wolterskluwer.springsecurity.security;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.security.authentication.dao.SaltSource;
import org.springframework.security.authentication.encoding.PasswordEncoder;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.jdbc.JdbcDaoImpl;

import com.wolterskluwer.springsecurity.security.SaltedUser;

/**
 * Extends the baseline Spring Security JdbcDaoImpl and implements change password functionality.
 * 

 * 
 * @author Angelo Cammarota
 */
public class CustomJdbcDaoImpl extends JdbcDaoImpl implements IChangePassword {

	@SuppressWarnings("deprecation")
	@Autowired
	private PasswordEncoder passwordEncoder;
	@Autowired
	private SaltSource saltSource;

	private KleosUserDetailsManager udm;
	

	public void changePassword(String username, String lawfirm, String password) {


		UserDetails user = udm.loadLawfirmUserByUserName(username, lawfirm);

		@SuppressWarnings("deprecation")
		String encodedPassword = passwordEncoder.encodePassword(password, saltSource.getSalt(user));
		getJdbcTemplate().update(
				"UPDATE dbo.aspnet_Membership SET Password = ? WHERE USERID = ? AND APPLICATIONID = ? ",
				encodedPassword, username,lawfirm );
	}

	protected UserDetails createUserDetails(String username,SaltedUser userFromUserQuery,List<GrantedAuthority> combinedAuthorities) {
		String returnUsername = userFromUserQuery.getUsername();

		if (!isUsernameBasedPrimaryKey()) {
			returnUsername = username;
		}
		
		userFromUserQuery.getSalt();

		return new SaltedUser(returnUsername, userFromUserQuery.getLawfirm(), userFromUserQuery.getPassword(), true, true, true, userFromUserQuery.isEnabled(),
				combinedAuthorities, ((SaltedUser) userFromUserQuery).getSalt(), ((SaltedUser) userFromUserQuery).getPasswordFormat());
	}

	@Override
	public void changePassword(String username, String password) {
		// TODO Auto-generated method stub
		
	}


}
