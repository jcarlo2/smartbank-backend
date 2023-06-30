package com.vendiola.smartbank.user;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class UserService {
    private final UserRepository userRepository;

    public boolean isUserExist(String username) {
        return userRepository.findByUsername(username).isPresent()
                ? true
                : false;
    }
}
