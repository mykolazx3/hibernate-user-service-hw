package mate.academy.security.impl;

import java.util.Optional;
import mate.academy.exception.AuthenticationException;
import mate.academy.exception.RegistrationException;
import mate.academy.lib.Inject;
import mate.academy.lib.Service;
import mate.academy.model.User;
import mate.academy.security.AuthenticationService;
import mate.academy.service.UserService;
import mate.academy.util.HashUtil;

@Service
public class AuthenticationServiceImpl implements AuthenticationService {
    @Inject
    private UserService userService;

    @Override
    public User login(String email, String password) throws AuthenticationException {
        Optional<User> userFromDbOptional = userService.findByEmail(email);
        if (userFromDbOptional.isEmpty()) {
            throw new AuthenticationException("Can't authenticate user");
        }
        User userFromDb = userFromDbOptional.get();
        String hashedPassword = HashUtil.hashPassword(password, userFromDb.getSalt());
        if (userFromDb.getPassword().equals(hashedPassword)) {
            return userFromDb;
        }
        throw new AuthenticationException("Can't authenticate user");
    }

    @Override
    public User register(String email, String password) throws RegistrationException {
        if (userService.findByEmail(email).isPresent()) {
            throw new RegistrationException("User with email " + email + " is already registered.");
        }
        if (email == null || email.isBlank()) {
            throw new RegistrationException("Email can't be blank ");
        }
        if (password == null || password.isBlank()) {
            throw new RegistrationException("Password can't be blank");
        }

        User newUser = new User();
        newUser.setEmail(email);
        newUser.setSalt(HashUtil.getSalt());
        newUser.setPassword(HashUtil.hashPassword(password, newUser.getSalt()));
        return userService.add(newUser);
    }
}
