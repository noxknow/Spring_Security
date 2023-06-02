package com.example.spring_security.service;

import com.example.spring_security.domain.User;
import com.example.spring_security.exception.AppException;
import com.example.spring_security.exception.ErrorCode;
import com.example.spring_security.repository.UserRepository;
import com.example.spring_security.utils.JwtTokenUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
// import org.slf4j.Logger;
// import org.slf4j.LoggerFactory;
@Service
@RequiredArgsConstructor
public class UserService {

    private final UserRepository userRepository;
    private final BCryptPasswordEncoder encoder;
//    private static final Logger log = LoggerFactory.getLogger(UserService.class);
    @Value("${jwt.secret}") // key를 가리기 위해서 사용한다.
    private String key;
    private Long expireTimeMs = 1000 * 60 * 60l;

    public String join(String userName, String passWord) {

        // userName 중복 check
        userRepository.findByUserName(userName)
                .ifPresent(user -> {
                    throw new AppException(ErrorCode.USERNAME_DUPLICATED, userName + "는 이미 있습니다.");
                });

        // 저장
        User user = User.builder()
                .userName(userName)
                .passWord(encoder.encode(passWord))
                .build();
        userRepository.save(user);

        return "SUCCESS";
    }

    public String login(String userName, String passWord) {
        // userName 없음
        User selectedUser = userRepository.findByUserName(userName)
                .orElseThrow(() -> new AppException(ErrorCode.USERNAME_NOT_FOUND, userName + "이 없습니다."));

        // passWord 틀림
//        log.info("selectedPw:{} pw:{}", selectedUser.getPassWord(), passWord);
        if (!encoder.matches(passWord, selectedUser.getPassWord())) {
            throw new AppException(ErrorCode.INVALID_PASSWORD, "패스워드를 잘못 입력하셨습니다.");
        }

        // 앞에서 Exception 안났으면 토큰 발행
        String token = JwtTokenUtil.createToken(selectedUser.getUserName(), key, expireTimeMs);

        return token;
    }
}
