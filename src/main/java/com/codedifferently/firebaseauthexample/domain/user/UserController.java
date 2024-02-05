package com.codedifferently.firebaseauthexample.domain.user;

import com.codedifferently.firebaseauthexample.security.models.FireBaseUser;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class UserController {

    private static Logger logger = LoggerFactory.getLogger(UserController.class);

    @GetMapping("/me")
    public ResponseEntity<FireBaseUser> getUserInfo(@AuthenticationPrincipal FireBaseUser user) {
        logger.info("A request was made by user with id {} and email {}",user.getUid(), user.getUid());
        return ResponseEntity.ok(user);
    }

}