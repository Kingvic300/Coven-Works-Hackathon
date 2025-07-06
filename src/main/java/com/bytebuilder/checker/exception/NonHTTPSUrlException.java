package com.bytebuilder.checker.exception;

public class NonHTTPSUrlException extends RuntimeException {
  public NonHTTPSUrlException(String message) {
    super(message);
  }
}
