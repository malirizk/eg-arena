package com.egarena.controller;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/stadiums")
public class StadiumController {
	
	private static final Logger LOGGER = LoggerFactory.getLogger(StadiumController.class);

	@RequestMapping(method = RequestMethod.GET, produces = MediaType.APPLICATION_JSON_VALUE)
//	@PreAuthorize("hasAuthority('ROOT')")
	public ResponseEntity<String> getAllStadiums() {
		LOGGER.debug("Inside getAllStadiums.");
		return new ResponseEntity<String>("OKKK", HttpStatus.OK);
	}
}
