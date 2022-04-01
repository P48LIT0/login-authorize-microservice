package com.example.jwt.exception.model;

import lombok.Getter;

@Getter
public class RoleNotFoundException extends RuntimeException {

    private int httpStatusCode;

    public RoleNotFoundException(String message, int httpStatusCode) {
        super(message);
        this.httpStatusCode = httpStatusCode;
    }
}