package com.egarena.security;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.Iterator;
import java.util.List;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.*;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.SignatureException;
import io.jsonwebtoken.UnsupportedJwtException;

public class TokenAuthenticationService {

	private static final Logger LOGGER = LoggerFactory.getLogger(TokenAuthenticationService.class);

	static final long EXPIRATIONTIME = 3600000; // 1 hour
	static final String SECRET = "ThisIsASecret";
	static final String TOKEN_PREFIX = "Bearer";
	static final String HEADER_STRING = "Authorization";

	// TODO : change to business exception
	static String addAuthentication(HttpServletResponse res, String username) throws Exception {
		LOGGER.info("Generateing JWT for user :{} ", username);
		String JWT = null;
		try {
			String roleNewValue = "USER";
			if (username.equals("bill")) {
				roleNewValue = "ROOT";
			}
			JWT = Jwts.builder().setSubject(username).claim("roles", roleNewValue).setIssuedAt(generateCurrentDate())
					.setExpiration(generateExpirationDate()).signWith(SignatureAlgorithm.HS512, SECRET).compact();
		} catch (Exception ex) {
			LOGGER.error("{} occured while building JWT for user : {}, , full stack trace is: [{}]",
					ex.getClass().getSimpleName(), username, ex);
			// TODO : change to business exception
			throw new Exception("{} occured while building JWT " + ex.getMessage());
		}
		res.addHeader(HEADER_STRING, TOKEN_PREFIX + " " + JWT);
		return JWT;
	}

	// TODO : change to business exception
	static String addAuthentication(Claims claims) throws Exception {
		LOGGER.info("Generateing Token for claims : {}", claims);
		String JWT;
		try {
			JWT = Jwts.builder().setClaims(claims).setIssuedAt(generateCurrentDate())
					.setExpiration(generateExpirationDate()).signWith(SignatureAlgorithm.HS512, SECRET).compact();
		} catch (Exception ex) {
			LOGGER.error("{} occured while building JWT from claims {}, full stack trace is: [{}]",
					ex.getClass().getSimpleName(), claims, ex);
			// TODO : change to business exception
			throw new Exception(ex.getClass().getSimpleName() + " occured while building JWT from claims");
		}
		return JWT;
	}

	// TODO : change to business exception
	static Authentication getAuthentication(HttpServletRequest request) throws Exception {
		String token = request.getHeader(HEADER_STRING);
		LOGGER.info("An attempt to validate JWT : {}", token);
		if (token != null) {
			token = token.replace(TOKEN_PREFIX, "").trim();
			String user = null;
			List<GrantedAuthority> grantedAuthorities;
			try {
				user = Jwts.parser().setSigningKey(SECRET).parseClaimsJws(token).getBody().getSubject();
				LOGGER.info("User {} has been extracted from JWT");
				String allRoles = Jwts.parser().setSigningKey(SECRET).parseClaimsJws(token).getBody().get("roles")
						.toString();
				LOGGER.info("User {} has the following roles [{}]", allRoles);
				List<String> roleString = Arrays.asList(allRoles.split(","));
				grantedAuthorities = new ArrayList<GrantedAuthority>();
				Iterator<String> it = roleString.iterator();
				while (it.hasNext()) {
					String currentRole = it.next();
					grantedAuthorities.add(new SimpleGrantedAuthority(currentRole));
					LOGGER.debug("User {} role {} added to GrantedAuthorities", user, currentRole);
				}

			} catch (MalformedJwtException | UnsupportedJwtException | SignatureException | ExpiredJwtException
					| IllegalArgumentException ex) {
				LOGGER.error("{} occured while parsing JWT, full stack trace: [{}]", ex.getClass().getSimpleName(), ex);
				SecurityContextHolder.clearContext();
				// TODO : change to business exception
				throw new Exception(ex.getClass().getSimpleName() + " occured while building JWT from claims");
			} catch (Exception ex) {
				LOGGER.error("{} occured while parsing JWT, full stack trace: [{}]", ex.getClass().getSimpleName(), ex);
				SecurityContextHolder.clearContext();
				// TODO : change to business exception
				throw new Exception(ex.getClass().getSimpleName() + " occured while building JWT from claims");
			}
			LOGGER.debug("Token : " + token + " relate to user : " + user);
			return new UsernamePasswordAuthenticationToken(user, null, grantedAuthorities);
		}
		return null;
	}

	public String refreshToken(String token) {
		String refreshedToken;
		try {
			final Claims claims = getClaimsFromToken(token);
			claims.setIssuedAt(generateCurrentDate());
			refreshedToken = addAuthentication(claims);
		} catch (Exception e) {
			refreshedToken = null;
		}
		return refreshedToken;
	}

	private Claims getClaimsFromToken(String token) {
		Claims claims;
		try {
			claims = Jwts.parser().setSigningKey(this.SECRET).parseClaimsJws(token).getBody();
		} catch (Exception e) {
			claims = null;
		}
		return claims;
	}

	private static Date generateCurrentDate() {
		return new Date(System.currentTimeMillis());
	}

	private static Date generateExpirationDate() {
		return new Date(System.currentTimeMillis() + EXPIRATIONTIME);
	}
}