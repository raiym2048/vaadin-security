package com.example.application.service.impl;

import com.example.application.enitites.User;
import com.example.application.enums.Role;
import com.example.application.repo.UserRepository;
import com.example.application.service.AuthService;
import com.vaadin.flow.component.notification.Notification;
import com.vaadin.flow.component.textfield.EmailField;
import com.vaadin.flow.component.textfield.PasswordField;
import com.vaadin.flow.router.NotFoundException;
import com.vaadin.flow.server.VaadinSession;
import org.apache.coyote.BadRequestException;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class AuthServiceImpl implements AuthService {
    private final AuthenticationManager authenticationManager;
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    public AuthServiceImpl(AuthenticationManager authenticationManager, UserRepository userRepository, PasswordEncoder passwordEncoder) {
        this.authenticationManager = authenticationManager;
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public void login(String emailField, String passwordField) {
        try {
            Authentication authentication =
                    authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(
                            emailField, passwordField
                    ));
            VaadinSession.getCurrent().setAttribute(Authentication.class, authentication);
            VaadinSession.getCurrent().setAttribute("user", authentication.getPrincipal());
            SecurityContextHolder.getContext().setAuthentication(authentication);
            Notification.show("login succ");

        }catch (Exception e){
            Notification.show("error login");
            throw new BadCredentialsException("Incorrect email or password");
        }

    }

    @Override
    public void register(String email, String password) {
        if (userRepository.findByEmail(email).isPresent())
            throw new NotFoundException("user is present");

        User user = new User();
        user.setEmail(email);
        user.setRole(Role.USER);
        user.setPassword(passwordEncoder.encode(password));
        userRepository.save(user);

    }
}
