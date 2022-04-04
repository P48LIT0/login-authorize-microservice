package com.example.jwt.exception.model;

import lombok.Getter;

@Getter
public class UserNotFoundException extends RuntimeException {

    private int httpStatusCode;

    public UserNotFoundException(String message, int httpStatusCode) {
        super(message);
        this.httpStatusCode = httpStatusCode;
    }
}