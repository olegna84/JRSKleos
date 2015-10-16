/**
 * 
 */
package com.wolterskluwer.springsecurity.security;

import java.sql.ResultSet;
import java.sql.SQLException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.RowCallbackHandler;
import org.springframework.jdbc.core.support.JdbcDaoSupport;
import org.springframework.security.authentication.dao.SaltSource;
import org.springframework.security.authentication.encoding.PasswordEncoder;
import org.springframework.security.core.userdetails.UserDetails;

/**
 * Secures the database by updating user passwords.
 * 
 * @author Angelo Cammarota
 */
public class DatabasePasswordSecurerBean extends JdbcDaoSupport {
	@Autowired
	private PasswordEncoder passwordEncoder;

	@Autowired
	private SaltSource saltSource;
	@Autowired
	private KleosUserDetailsManager userDetailsService;

	public void secureDatabase() {
		//DB [PLT_VNEXT_EU_ELSAMEMBERSHIP]
		/*
		getJdbcTemplate().query("select u.username, m.password, a.ApplicationName, m.PasswordFormat, m.PasswordSalt, u.userId, u.applicationId "
				+ "from dbo.aspnet_Membership m, "
				+ "dbo.aspnet_Applications a, "
				+ "dbo.aspnet_Users u "
				+ "where m.ApplicationId=a.ApplicationId and u.UserId=m.UserId", new RowCallbackHandler(){
					@Override
					public void processRow(ResultSet rs) throws SQLException {
						String username = rs.getString(1);
						String password = rs.getString(2);
						String lawfirm=rs.getString(3);
						String passwordFormat=rs.getString(4);
						String userID=rs.getString(5);
						String applicationId=rs.getString(6);


						SaltedUser user = userDetailsService.loadLawfirmUserByUserName(username, lawfirm);
						String encodedPassword="";

						//if the password is encoded
						if(passwordFormat.equalsIgnoreCase("1")){
							encodedPassword = passwordEncoder.encodePassword(password, saltSource.getSalt(user));
						}
						else{
							encodedPassword=password;
						}

						//				String encodedPassword = passwordEncoder.encodePassword(password, null);
						getJdbcTemplate().update("update dbo.aspnet_Membership set password = ? where UserId = ? and applicationId= ? ", 
								encodedPassword, 
								userID,
								applicationId);
						logger.debug("Updating password for username: "+username+" and lawfirm: "+lawfirm+" to: "+encodedPassword);
					}			
				});*/
	}
}
