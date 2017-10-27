package com.egarena.security;

import java.io.IOException;
import java.util.Collections;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import com.egarena.model.UserCredential;
import com.fasterxml.jackson.databind.ObjectMapper;

public class AuthenticationFilter extends AbstractAuthenticationProcessingFilter {

	private static final Logger LOGGER = LoggerFactory.getLogger(AuthenticationFilter.class);

	public AuthenticationFilter(String url, AuthenticationManager authManager) {
		super(new AntPathRequestMatcher(url));
		setAuthenticationManager(authManager);
	}

	@Override
	public Authentication attemptAuthentication(HttpServletRequest req, HttpServletResponse res)
			throws AuthenticationException, IOException, ServletException {

		UserCredential creds = (UserCredential) new ObjectMapper().readValue(req.getInputStream(), UserCredential.class);

		LOGGER.info("Attempt to autenticate customer with username : " + creds.getUsername());

		return getAuthenticationManager().authenticate(new UsernamePasswordAuthenticationToken(creds.getUsername(),
				creds.getPassword(), Collections.emptyList()));
	}

	@Override
	protected void successfulAuthentication(HttpServletRequest req, HttpServletResponse res, FilterChain chain,
			Authentication auth) throws IOException, ServletException {

		LOGGER.info("Successfully authenticate Customer with username : " + auth.getName() + " with details : "
				+ auth.getDetails());

		try {
			TokenAuthenticationService.addAuthentication(res, auth.getName());
		} catch (Exception e) {
			logger.error("Authentication Exception occured");
			res.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Authorization Exception has occured");
		}
	}

	protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response,
			AuthenticationException failed) throws IOException, ServletException {
		LOGGER.error("An Error Occured while adding authentication token in Redis Cache");
		SecurityContextHolder.clearContext();
		response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Authorization Exception has occured");
	}
}
