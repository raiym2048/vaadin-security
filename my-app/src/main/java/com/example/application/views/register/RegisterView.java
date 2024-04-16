package com.example.application.views.register;

import com.example.application.service.AuthService;
import com.vaadin.flow.component.UI;
import com.vaadin.flow.component.button.Button;
import com.vaadin.flow.component.notification.Notification;
import com.vaadin.flow.component.orderedlayout.VerticalLayout;
import com.vaadin.flow.component.textfield.EmailField;
import com.vaadin.flow.component.textfield.PasswordField;
import com.vaadin.flow.router.NotFoundException;
import com.vaadin.flow.router.Route;
import com.vaadin.flow.server.auth.AnonymousAllowed;
import org.apache.coyote.BadRequestException;
import org.springframework.security.authentication.BadCredentialsException;

@Route("register")
@AnonymousAllowed
public class RegisterView extends VerticalLayout {
    private final AuthService authService;

    private EmailField emailField;
    private PasswordField passwordField;

    private Button login;
    private Button register;

    public RegisterView(AuthService authService){

        this.authService = authService;
        this.emailField = new EmailField("email");
        emailField.setPlaceholder("Email");
        passwordField = new PasswordField("password");
        passwordField.setPlaceholder("Password");

        login = new Button("Login");

        login.addClickListener( e -> {
            UI.getCurrent().navigate("login");
        });
        register = new Button("register");
        register.addClickListener( e -> {
            try {
                authService.register(emailField.getValue(), passwordField.getValue());
            }catch (Exception exception){
                throw new NotFoundException("sfaafiysjk");
            }
        });

        add(emailField, passwordField, login, register);

    }
}
