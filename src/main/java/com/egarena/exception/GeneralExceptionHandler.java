package com.egarena.exception;

import java.util.logging.Logger;

import javax.validation.ConstraintViolation;
import javax.validation.ConstraintViolationException;

import org.springframework.beans.ConversionNotSupportedException;
import org.springframework.beans.TypeMismatchException;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.validation.BindException;
import org.springframework.web.HttpMediaTypeNotAcceptableException;
import org.springframework.web.HttpMediaTypeNotSupportedException;
import org.springframework.web.HttpRequestMethodNotSupportedException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.MissingPathVariableException;
import org.springframework.web.bind.MissingServletRequestParameterException;
import org.springframework.web.bind.ServletRequestBindingException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.context.request.WebRequest;
import org.springframework.web.multipart.support.MissingServletRequestPartException;
import org.springframework.web.servlet.NoHandlerFoundException;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;
import org.springframework.web.servlet.mvc.multiaction.NoSuchRequestHandlingMethodException;


@RestControllerAdvice
@EnableWebMvc
public class GeneralExceptionHandler extends ResponseEntityExceptionHandler {

	// private static PropertiesReader props = PropertiesReader.getInstance("config.properties");
	private Logger logger = Logger.getLogger(GeneralExceptionHandler.class.getName());

	@Override
	protected ResponseEntity<Object> handleHttpMediaTypeNotAcceptable(HttpMediaTypeNotAcceptableException e,
			HttpHeaders headers, HttpStatus status, WebRequest request) {

		ErrorResponse errorResponse = new ErrorResponse();
		errorResponse.setDescription(e.getMessage());
		// errorResponse.setTransactionId(request.getHeader(props.getProperty(CommonConstants.TRX_HEADER)));
		errorResponse.setError(HttpStatus.BAD_REQUEST.name());
		errorResponse.setMessage(HttpStatus.BAD_REQUEST.name());

		return new ResponseEntity<Object>(errorResponse, HttpStatus.BAD_REQUEST);
	}

	@Override
	protected ResponseEntity<Object> handleHttpMediaTypeNotSupported(HttpMediaTypeNotSupportedException e,
			HttpHeaders headers, HttpStatus status, WebRequest request) {

		ErrorResponse errorResponse = new ErrorResponse();
		errorResponse.setDescription(e.getMessage());
		// errorResponse.setTransactionId(request.getHeader(props.getProperty(CommonConstants.TRX_HEADER)));
		errorResponse.setError(HttpStatus.UNSUPPORTED_MEDIA_TYPE.name());
		errorResponse.setMessage(HttpStatus.UNSUPPORTED_MEDIA_TYPE.name());

		return new ResponseEntity<Object>(errorResponse, HttpStatus.UNSUPPORTED_MEDIA_TYPE);
	}

	@Override
	protected ResponseEntity<Object> handleConversionNotSupported(ConversionNotSupportedException e,
			HttpHeaders headers, HttpStatus status, WebRequest request) {

		ErrorResponse errorResponse = new ErrorResponse();
		errorResponse.setDescription(e.getMessage());
		// errorResponse.setTransactionId(request.getHeader(props.getProperty(CommonConstants.TRX_HEADER)));
		errorResponse.setError(HttpStatus.BAD_REQUEST.name());
		errorResponse.setMessage(HttpStatus.BAD_REQUEST.name());

		return new ResponseEntity<Object>(errorResponse, HttpStatus.BAD_REQUEST);
	}

	@Override
	protected ResponseEntity<Object> handleMissingPathVariable(MissingPathVariableException e, HttpHeaders headers,
			HttpStatus status, WebRequest request) {

		ErrorResponse errorResponse = new ErrorResponse();
		errorResponse.setDescription(e.getMessage());
		// errorResponse.setTransactionId(request.getHeader(props.getProperty(CommonConstants.TRX_HEADER)));
		errorResponse.setError(HttpStatus.BAD_REQUEST.name());
		errorResponse.setMessage(HttpStatus.BAD_REQUEST.name());

		return new ResponseEntity<Object>(errorResponse, HttpStatus.BAD_REQUEST);
	}

	@Override
	protected ResponseEntity<Object> handleMissingServletRequestPart(MissingServletRequestPartException e,
			HttpHeaders headers, HttpStatus status, WebRequest request) {

		ErrorResponse errorResponse = new ErrorResponse();
		errorResponse.setDescription(e.getMessage());
		// errorResponse.setTransactionId(request.getHeader(props.getProperty(CommonConstants.TRX_HEADER)));
		errorResponse.setError(HttpStatus.BAD_REQUEST.name());
		errorResponse.setMessage(HttpStatus.BAD_REQUEST.name());

		return new ResponseEntity<Object>(errorResponse, HttpStatus.BAD_REQUEST);
	}

	@Override
	protected ResponseEntity<Object> handleNoHandlerFoundException(NoHandlerFoundException e, HttpHeaders headers,
			HttpStatus status, WebRequest request) {

		ErrorResponse errorResponse = new ErrorResponse();
		// errorResponse.setDescription(e.getMessage());
//		errorResponse.setTransactionId(request.getHeader(props.getProperty(CommonConstants.TRX_HEADER)));
		errorResponse.setError(HttpStatus.BAD_REQUEST.name());
		errorResponse.setMessage(HttpStatus.BAD_REQUEST.name());

		return new ResponseEntity<Object>(errorResponse, HttpStatus.BAD_REQUEST);
	}

	@Override
	protected ResponseEntity<Object> handleServletRequestBindingException(ServletRequestBindingException e,
			HttpHeaders headers, HttpStatus status, WebRequest request) {

		ErrorResponse errorResponse = new ErrorResponse();
		errorResponse.setDescription(e.getMessage());
//		errorResponse.setTransactionId(request.getHeader(props.getProperty(CommonConstants.TRX_HEADER)));
		errorResponse.setError(HttpStatus.BAD_REQUEST.name());
		errorResponse.setMessage(HttpStatus.BAD_REQUEST.name());

		return new ResponseEntity<Object>(errorResponse, HttpStatus.BAD_REQUEST);
	}

	@Override
	protected ResponseEntity<Object> handleTypeMismatch(TypeMismatchException e, HttpHeaders headers, HttpStatus status,
			WebRequest request) {

		ErrorResponse errorResponse = new ErrorResponse();
		errorResponse.setDescription(e.getMessage());
		// errorResponse.setTransactionId(request.getHeader(props.getProperty(CommonConstants.TRX_HEADER)));
		errorResponse.setError(HttpStatus.BAD_REQUEST.name());
		errorResponse.setMessage(HttpStatus.BAD_REQUEST.name());

		return new ResponseEntity<Object>(errorResponse, HttpStatus.BAD_REQUEST);
	}

	@Override
	protected ResponseEntity<Object> handleMethodArgumentNotValid(MethodArgumentNotValidException e,
			HttpHeaders headers, HttpStatus status, WebRequest request) {

		ErrorResponse errorResponse = new ErrorResponse();
		errorResponse.setDescription(e.getMessage());
		// errorResponse.setTransactionId(request.getHeader(props.getProperty(CommonConstants.TRX_HEADER)));
		errorResponse.setError(HttpStatus.BAD_REQUEST.name());
		errorResponse.setMessage(HttpStatus.BAD_REQUEST.name());

		return new ResponseEntity<Object>(errorResponse, HttpStatus.BAD_REQUEST);
	}

	@Override
	protected ResponseEntity<Object> handleMissingServletRequestParameter(MissingServletRequestParameterException e,
			HttpHeaders headers, HttpStatus status, WebRequest request) {

		ErrorResponse errorResponse = new ErrorResponse();
		errorResponse.setDescription(e.getMessage());
		// errorResponse.setTransactionId(request.getHeader(props.getProperty(CommonConstants.TRX_HEADER)));
		errorResponse.setError(HttpStatus.BAD_REQUEST.name());
		errorResponse.setMessage(HttpStatus.BAD_REQUEST.name());

		return new ResponseEntity<Object>(errorResponse, HttpStatus.BAD_REQUEST);
	}

	@Override
	protected ResponseEntity<Object> handleHttpRequestMethodNotSupported(HttpRequestMethodNotSupportedException e,
			HttpHeaders headers, HttpStatus status, WebRequest request) {

		ErrorResponse errorResponse = new ErrorResponse();
		errorResponse.setDescription(e.getMessage());
		// errorResponse.setTransactionId(request.getHeader(props.getProperty(CommonConstants.TRX_HEADER)));
		errorResponse.setError(HttpStatus.METHOD_NOT_ALLOWED.name());
		errorResponse.setMessage(HttpStatus.METHOD_NOT_ALLOWED.name());

		return new ResponseEntity<Object>(errorResponse, HttpStatus.METHOD_NOT_ALLOWED);
	}

	@Override
	protected ResponseEntity<Object> handleHttpMessageNotReadable(HttpMessageNotReadableException e,
			HttpHeaders headers, HttpStatus status, WebRequest request) {

		ErrorResponse errorResponse = new ErrorResponse();
		errorResponse.setDescription(e.getMessage());
		// errorResponse.setTransactionId(request.getHeader(props.getProperty(CommonConstants.TRX_HEADER)));
		errorResponse.setError(HttpStatus.BAD_REQUEST.name());
		errorResponse.setMessage(HttpStatus.BAD_REQUEST.name());

		return new ResponseEntity<Object>(errorResponse, HttpStatus.BAD_REQUEST);
	}

	@Override
	protected ResponseEntity<Object> handleBindException(BindException e, HttpHeaders headers, HttpStatus status,
			WebRequest request) {
		ErrorResponse errorResponse = new ErrorResponse();
		errorResponse.setDescription(e.getMessage());
		// errorResponse.setTransactionId(request.getHeader(props.getProperty(CommonConstants.TRX_HEADER)));
		errorResponse.setError(HttpStatus.BAD_REQUEST.name());
		errorResponse.setMessage(HttpStatus.BAD_REQUEST.name());

		return new ResponseEntity<Object>(errorResponse, HttpStatus.BAD_REQUEST);
	}

	@Override
	protected ResponseEntity<Object> handleNoSuchRequestHandlingMethod(NoSuchRequestHandlingMethodException e,
			HttpHeaders headers, HttpStatus status, WebRequest request) {
		ErrorResponse errorResponse = new ErrorResponse();
		errorResponse.setDescription(e.getMessage());
		// errorResponse.setTransactionId(request.getHeader(props.getProperty(CommonConstants.TRX_HEADER)));
		errorResponse.setError(HttpStatus.BAD_REQUEST.name());
		errorResponse.setMessage(HttpStatus.BAD_REQUEST.name());

		return new ResponseEntity<Object>(errorResponse, HttpStatus.BAD_REQUEST);
	}

	@ExceptionHandler(ConstraintViolationException.class)
	@ResponseBody
	public ResponseEntity<ErrorResponse> handleConstraintViolationException(ConstraintViolationException e,
			WebRequest request) {

		ErrorResponse errorResponse = new ErrorResponse();
		String key = "";
		StringBuilder message = new StringBuilder("");
		for (ConstraintViolation violation : e.getConstraintViolations()) {
			if (violation.getPropertyPath() != null) {
				key = violation.getPropertyPath().toString();
				message.append(" " + key + " " + violation.getMessage());
			}
		}
		errorResponse.setDescription(message.toString());
//		errorResponse.setTransactionId(request.getHeader(props.getProperty(CommonConstants.TRX_HEADER)));
		errorResponse.setError(HttpStatus.BAD_REQUEST.name());
		errorResponse.setMessage(HttpStatus.BAD_REQUEST.name());

		return new ResponseEntity<ErrorResponse>(errorResponse, HttpStatus.BAD_REQUEST);

	}

	@ExceptionHandler(BusinessException.class)
	@ResponseBody
	public ResponseEntity<ErrorResponse> processMethodNotSupportedException(BusinessException e, WebRequest request) {
		logger.severe(e.toString());

		ErrorResponse errorResponse = new ErrorResponse();

		errorResponse.setDescription(e.getMessage());
//		errorResponse.setTransactionId(request.getHeader(props.getProperty(CommonConstants.TRX_HEADER)));
		if (e.getHttpStatus() == null) {
			errorResponse.setMessage(HttpStatus.INTERNAL_SERVER_ERROR.name());
			errorResponse.setError(HttpStatus.INTERNAL_SERVER_ERROR.name());
			return new ResponseEntity<ErrorResponse>(errorResponse, HttpStatus.INTERNAL_SERVER_ERROR);
		}
		errorResponse.setMessage(e.getHttpStatus().name());
		errorResponse.setError(e.getHttpStatus().name());
		errorResponse.setAdditionalInfo(e.getExtraResponseData());
		return new ResponseEntity<ErrorResponse>(errorResponse, e.getHttpStatus());

	}

	@ExceptionHandler(AuthenticationException.class)
	@ResponseBody
	public ResponseEntity<ErrorResponse> procesAuthenticationException(AuthenticationException e, WebRequest request) {
		logger.severe(e.toString());
		ErrorResponse errorResponse = new ErrorResponse();
		errorResponse.setDescription(e.getMessage());
		// errorResponse.setTransactionId(request.getHeader(props.getProperty(CommonConstants.TRX_HEADER)));
		errorResponse.setMessage(HttpStatus.FORBIDDEN.name());
		errorResponse.setError(HttpStatus.FORBIDDEN.name());

		return new ResponseEntity<ErrorResponse>(errorResponse, HttpStatus.FORBIDDEN);

	}

	@ExceptionHandler(Exception.class)
	@ResponseBody
	public ResponseEntity<ErrorResponse> processRuntimeException(Exception e, WebRequest request) {
		logger.severe(e.toString());
		ErrorResponse errorResponse = new ErrorResponse();
		errorResponse.setDescription(e.getMessage());
		// errorResponse.setTransactionId(request.getHeader(props.getProperty(CommonConstants.TRX_HEADER)));
		errorResponse.setMessage(HttpStatus.INTERNAL_SERVER_ERROR.name());
		errorResponse.setError(HttpStatus.INTERNAL_SERVER_ERROR.name());

		return new ResponseEntity<ErrorResponse>(errorResponse, HttpStatus.INTERNAL_SERVER_ERROR);
	}

	@ExceptionHandler(Throwable.class)
	@ResponseBody
	public ResponseEntity<ErrorResponse> handle(Throwable e, WebRequest request) {
		logger.severe(e.toString());
		ErrorResponse errorResponse = new ErrorResponse();
		errorResponse.setDescription(e.getMessage());
		// errorResponse.setTransactionId(request.getHeader(props.getProperty(CommonConstants.TRX_HEADER)));
		errorResponse.setMessage(HttpStatus.INTERNAL_SERVER_ERROR.name());
		errorResponse.setError(HttpStatus.INTERNAL_SERVER_ERROR.name());

		return new ResponseEntity<ErrorResponse>(errorResponse, HttpStatus.INTERNAL_SERVER_ERROR);
	}

}