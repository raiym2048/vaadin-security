package com.example.application.views.login;

import com.example.application.service.AuthService;
import com.vaadin.flow.component.UI;
import com.vaadin.flow.component.orderedlayout.VerticalLayout;
import com.vaadin.flow.component.textfield.EmailField;
import com.vaadin.flow.component.textfield.PasswordField;
import com.vaadin.flow.router.BeforeEnterEvent;
import com.vaadin.flow.router.BeforeEnterObserver;
import com.vaadin.flow.router.Route;
import com.vaadin.flow.server.auth.AnonymousAllowed;
import org.springframework.security.authentication.BadCredentialsException;
import com.vaadin.flow.component.button.Button;
import com.vaadin.flow.component.notification.Notification;

@Route("login")
@AnonymousAllowed
public class LoginView extends VerticalLayout implements BeforeEnterObserver {

    private final AuthService authService;

    private EmailField emailField;
    private PasswordField passwordField;

    private Button login;
    private Button register;

    public LoginView(AuthService authService){
        this.authService = authService;
        this.emailField = new EmailField("email");
        emailField.setPlaceholder("Email");
        passwordField = new PasswordField("password");
        passwordField.setPlaceholder("Password");

        login = new Button("Login");

        login.addClickListener( e -> {
            try {
                authService.login(emailField.getValue(), passwordField. getValue());
                Notification.show("successfully login");
                UI.getCurrent().navigate("dashboard");
            }catch (Exception exception){
                Notification.show("incorrect p/login");
                throw new BadCredentialsException(exception.getMessage());
            }
        });
        register = new Button("register");
        register.addClickListener( e -> {
            UI.getCurrent().navigate("register");
        });

        add(emailField, passwordField, login, register);

    }
    @Override
    public void beforeEnter(BeforeEnterEvent beforeEnterEvent) {

    }
}
