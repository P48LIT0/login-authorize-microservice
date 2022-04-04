package com.example.jwt.exception.model;

import lombok.Getter;

@Getter
public class UserAlreadyExistsException extends RuntimeException {

    private int httpStatusCode;

    public UserAlreadyExistsException(String message, int httpStatusCode) {
        super(message);
        this.httpStatusCode = httpStatusCode;
    }
}
