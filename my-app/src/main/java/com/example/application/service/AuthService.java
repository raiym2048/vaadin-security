package com.example.application.service;

import com.example.application.enitites.User;
import com.vaadin.flow.component.textfield.EmailField;
import com.vaadin.flow.component.textfield.PasswordField;

import java.util.Optional;

public interface AuthService {
    Optional<User> getUser(String username, String password);

    void login(String emailField, String passwordField);

    void register(String value, String value1);
}
