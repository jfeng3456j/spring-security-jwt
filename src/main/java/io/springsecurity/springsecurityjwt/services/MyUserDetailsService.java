package io.springsecurity.springsecurityjwt.services;

import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;


import java.util.ArrayList;

@Service
public class MyUserDetailsService implements UserDetailsService {

    //https://stackoverflow.com/questions/49582971/encoded-password-does-not-look-like-bcrypt
    private BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();

    @Override
    public UserDetails loadUserByUsername(String userName) throws UsernameNotFoundException {
        return new User("user1", encoder.encode("user1"), new ArrayList<>());
        }
}

