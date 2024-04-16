package com.example.application.service;

import com.vaadin.flow.component.textfield.EmailField;
import com.vaadin.flow.component.textfield.PasswordField;

public interface AuthService {
    void login(String emailField, String passwordField);

    void register(String value, String value1);
}
