package com.example.duel.user;

import com.example.duel._core.errors.ExceptionCode;
import com.example.duel._core.errors.CustomException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.example.duel._core.security.JWTProvider;
import com.example.duel._core.utils.RedisUtils;
import com.example.duel.alarm.AlarmRepository;
import com.example.duel.comment.Comment;
import com.example.duel.comment.CommentRepository;
import com.example.duel.roadmap.Roadmap;
import com.example.duel.roadmap.RoadmapRepository;
import com.example.duel.roadmap.relation.UserRoadmap;
import com.example.duel.roadmap.relation.UserRoadmapRepository;
import com.example.duel.step.Step;
import com.example.duel.step.StepRepository;
import com.example.duel.step.reference.ReferenceRepository;
import com.example.duel.step.relation.UserStep;
import com.example.duel.step.relation.UserStepRepository;
import com.example.duel.til.Til;
import com.example.duel.til.TilRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.mail.javamail.JavaMailSender;
import javax.mail.Message;
import javax.mail.internet.MimeMessage;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.stream.Collectors;

@Transactional
@RequiredArgsConstructor
@Service
public class UserService {

    private final PasswordEncoder passwordEncoder;
    private final UserRepository userRepository;
    private final JavaMailSender javaMailSender;
    private final RedisUtils redisUtils;
    private final TilRepository tilRepository;
    private final UserRoadmapRepository userRoadmapRepository;
    private final UserStepRepository userStepRepository;
    private final RoadmapRepository roadmapRepository;
    private final CommentRepository commentRepository;
    private final StepRepository stepRepository;
    private final ReferenceRepository referenceRepository;
    private final AlarmRepository alarmRepository;

    private String defaultImage = "/assets/icons/ic_profile";

    // (회원가입) 이메일 중복 체크 후 인증코드 전송
    @Transactional
    public void checkEmail(UserRequest.CheckEmailDTO requestDTO) {
        checkEmail(requestDTO.email());
        //sendCode(requestDTO.email());
    }

    // 인증코드 전송
    @Transactional
    public void sendEmailCode(UserRequest.SendEmailCodeDTO requestDTO) {
        findByEmail(requestDTO.email());
        //sendCode(requestDTO.email());
    }

    // 인증코드 확인
    @Transactional
    public UserResponse.CheckEmailCodeDTO checkEmailCode(UserRequest.CheckEmailCodeDTO requestDTO) {
        String code = redisUtils.getData(requestDTO.email()); // 이메일로 찾은 코드

        if (code==null)
            throw new CustomException(ExceptionCode.CODE_EXPIRED);
        else if (!code.equals(requestDTO.code()))
            throw new CustomException(ExceptionCode.CODE_WRONG);

        redisUtils.deleteData(requestDTO.email()); // 인증 완료 후 인증코드 삭제

        return new UserResponse.CheckEmailCodeDTO(requestDTO.email());
    }


    // 회원가입
    @Transactional
    public void join(UserRequest.JoinDTO requestDTO) {
        checkEmail(requestDTO.email());
        
        if (!requestDTO.password().equals(requestDTO.passwordConfirm()))
            throw new CustomException(ExceptionCode.USER_PASSWORD_WRONG);

        User user = User.builder()
                .email(requestDTO.email())
                .name(requestDTO.name())
                .password(passwordEncoder.encode(requestDTO.password()))
                .image(createDefaultImage(defaultImage))
                .role(Role.ROLE_USER)
                .build();

        userRepository.save(user);
    }

    // 로그인
    @Transactional
    public UserResponse.TokenDTO login(UserRequest.LoginDTO requestDTO) {
        User user = findByEmail(requestDTO.email());

        if(!passwordEncoder.matches(requestDTO.password(), user.getPassword()))
            throw new CustomException(ExceptionCode.USER_PASSWORD_WRONG);

        return createToken(user);
    }

    // 토큰 재발급
    @Transactional
    public UserResponse.TokenDTO refresh(String refreshToken) {
        DecodedJWT decodedJWT = JWTProvider.verify(refreshToken);
        Long userId = decodedJWT.getClaim("id").asLong();

        if (!redisUtils.existData(userId.toString()))
            throw new CustomException(ExceptionCode.TOKEN_EXPIRED);

        User user = findById(userId);

        return createToken(user);
    }

    // 비밀번호 변경
    @Transactional
    public void changePassword(UserRequest.ChangePwdDTO requestDTO) {
        User user = findByEmail(requestDTO.email());

        String enPassword = passwordEncoder.encode(requestDTO.password());
        user.updatePassword(enPassword);
    }

   
}
