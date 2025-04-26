package org.jad.auth.service;

import lombok.RequiredArgsConstructor;
import org.jad.auth.User;
import org.jad.auth.repository.UserRepository;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Date;

@Service
@RequiredArgsConstructor
public class UserServiceImpl implements UserService{

    private final UserRepository userRepository;



    @Override
    public UserDetailsService userDetailsService(){
        return new UserDetailsService() {
            @Override
            public UserDetails loadUserByUsername(String username) {
                User user = userRepository.findByUsername(username);
                if (user == null) {
                    throw new UsernameNotFoundException("Collaborateur non trouvé avec l'email : " + username);
                }
//                user.setDerniereConnexion(new Date());
                userRepository.save(user);
                return user;
            }


        };
    }

    @Override
    public boolean isValidEmail(String email) {
        return userRepository.existsByEmail(email);
    }

}