package com.bedrock.springsecurityjwt.exception;


public class AuthenticationException extends Exception {

  public AuthenticationException(String message, Throwable cause) {
    super(message, cause);
  }
}
