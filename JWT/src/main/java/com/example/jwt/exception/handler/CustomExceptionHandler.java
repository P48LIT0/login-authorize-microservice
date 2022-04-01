package com.example.jwt.exception.handler;

import com.example.jwt.exception.model.RoleNotFoundException;
import com.example.jwt.exception.model.UserAlreadyExistsException;
import com.example.jwt.payload.MessageResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;

@Slf4j
@ControllerAdvice
public class CustomExceptionHandler {

    @ExceptionHandler(UserAlreadyExistsException.class)
    public MessageResponse handleUserAlreadyExistsException(UserAlreadyExistsException e) {
        log.error(e.getMessage());
        return new MessageResponse(e.getHttpStatusCode() ,e.getMessage());
    }

    @ExceptionHandler(RoleNotFoundException.class)
    public MessageResponse handleRoleNotFoundException(UserAlreadyExistsException e) {
        log.error(e.getMessage());
        return new MessageResponse(e.getHttpStatusCode() ,e.getMessage());
    }

}
