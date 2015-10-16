package com.wolterskluwer.springsecurity.security;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.List;

import org.springframework.dao.DataAccessException;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
/**
 * 
 * @author Angelo Cammarota
 *
 * The purpose of this class is to extend the functionality
 * provided by the JdbcDaoImpl class. The extra features the class
 * provides is availability of the domain name selection for a 
 * particular user.
 */
public class KleosUserDetailsManager extends JdbcUserDetailsManager {
	/**
	 * Set the default value for
	 */

	public static final String USER_BY_USERNAME_LAWFIRM="select u.username, m.password, a.ApplicationName, m.PasswordFormat, m.SaltPassword "
			+ "from dbo.aspnet_Membership m, "
			+ "dbo.aspnet_Applications a, "
			+ "dbo.aspnet_Users u "
			+ "where m.ApplicationId=a.ApplicationId and u.UserId=m.UserId "
			+ "and u.username=? and a.ApplicationName=?";
	/*public static final String USER_BY_USERNAME_LAWFIRM = "select users.username,users.password,users.enabled,domain.domainname "
    		+ "from users,domain where users.domainid = domain.domainid and users.username = ? and domain.domainname = ?";*/

	//    public static final String AUTHORITIES_BY_USERNAME_LAWFIRM = "select u.username as username,p.permissionname as authorityname "
	//    		+ "from users u,roles r,permissions p,userrole ur, rolepermission rp,domain d where u.username = ? and "
	//    		+ "d.domainid = u.domainid and d.domainname = ? and ur.roleid = r.roleid and ur.userid = u.userid and "
	//    		+ "r.roleid = rp.roleid and rp.permissionid = p.permissionid";

	// private String authoritiesByUserNameDomainQuery = AUTHORITIES_BY_USERNAME_DOMAIN;

	//    public String getAuthoritiesByUserNameDomainQuery() {
	//        return authoritiesByUserNameDomainQuery;
	//    }
	// 
	//    public void setAuthoritiesByUserNameDomainQuery(
	//            String authoritiesByUserNameDomainQuery) {
	//        this.authoritiesByUserNameDomainQuery = authoritiesByUserNameDomainQuery;
	//    }

	private String userByUserNameLawfirmQuery = USER_BY_USERNAME_LAWFIRM;



	@SuppressWarnings("null")
	public SaltedUser loadLawfirmUserByUserName(String username,String lawfirm) throws UsernameNotFoundException,
	DataAccessException {
		List<SaltedUser> users = loadLawfirmUsersByUserName(username,lawfirm);

		if (users.size() == 0) {
			throw new UsernameNotFoundException(
					messages.getMessage("JdbcDaoImpl.notFound", new Object[]{username}, "Username {0} not found"), username);
		}

		SaltedUser lawfirmUser = users.get(0); // contains no GrantedAuthority[]

		/* Set<GrantedAuthority> dbAuthsSet = new HashSet<GrantedAuthority>();

        if (this.getEnableAuthorities()) {
            dbAuthsSet.addAll(loadDomainUserAuthorities(username, domainname));
        }

        if (this.getEnableGroups()) {
            dbAuthsSet.addAll(loadGroupAuthorities(domainUser.getUsername()));
        }*/

		List<GrantedAuthority> dbAuths = null ;

		addCustomAuthorities(lawfirmUser.getUsername(), dbAuths);

		if (dbAuths.size() == 0) {
			throw new UsernameNotFoundException(
					messages.getMessage("JdbcDaoImpl.noAuthority",
							new Object[] {username}, "User {0} has no GrantedAuthority"), username);
		}

		return createLawfirmUserDetails(username, lawfirmUser,dbAuths);
	}


	protected List<SaltedUser> loadLawfirmUsersByUserName(String username,String lawfirm) {
		return getJdbcTemplate().query(userByUserNameLawfirmQuery, new String[] {username,lawfirm}, new RowMapper<SaltedUser>() {
			public SaltedUser mapRow(ResultSet rs, int rowNum) throws SQLException {
				String username = rs.getString(1);
				String password = rs.getString(2);
				boolean enabled = rs.getBoolean(3);
				String lawfirm = rs.getString(4);
				String passwordFormat=rs.getString(5);
				String saltPassword=rs.getString(6);
				return new SaltedUser(username, lawfirm, password, enabled, true, true, true, AuthorityUtils.NO_AUTHORITIES, saltPassword, passwordFormat );
			}

		});
	}

	//    protected List<GrantedAuthority> loadDomainUserAuthorities(String username,String domain) {
	//        return getJdbcTemplate().query(authoritiesByUserNameDomainQuery, new String[] {username,domain}, new RowMapper<GrantedAuthority>() {
	//            public GrantedAuthority mapRow(ResultSet rs, int rowNum) throws SQLException {
	//                String roleName = getRolePrefix() + rs.getString(2);
	//                GrantedAuthorityImpl authority = new GrantedAuthorityImpl(roleName);
	// 
	//                return authority;
	//            }
	//        });
	//    }

	protected SaltedUser createLawfirmUserDetails(String username, SaltedUser userFromUserQuery,
			List<GrantedAuthority> combinedAuthorities) {
		String returnUsername = userFromUserQuery.getUsername();

		if (!this.isUsernameBasedPrimaryKey()) {
			returnUsername = username;
		}



		return new SaltedUser(returnUsername, userFromUserQuery.getLawfirm(), userFromUserQuery.getPassword(), true, true, true, userFromUserQuery.isEnabled(),
				combinedAuthorities, ((SaltedUser) userFromUserQuery).getSalt(), ((SaltedUser) userFromUserQuery).getPasswordFormat());
	}


	public String getUserByUserNameLawfirmQuery() {
		return userByUserNameLawfirmQuery;
	}


	public void setUserByUserNameLawfirmQuery(String userByUserNameLawfirmQuery) {
		this.userByUserNameLawfirmQuery = userByUserNameLawfirmQuery;
	}
}

