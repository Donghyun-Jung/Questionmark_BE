package com.example.duel.user;

import com.example.duel._core.security.CustomUserDetails;
import com.example.duel._core.security.JWTProvider;
import com.example.duel._core.utils.ApiUtils;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.validation.Errors;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;

@RequiredArgsConstructor
@RestController
@RequestMapping("/api")
public class UserController {

    private final UserService userService;

    // 이메일 중복 체크 (후 인증코드 전송)
    @PostMapping("/email/check")
    public ResponseEntity<?> checkEmail(@RequestBody @Valid UserRequest.CheckEmailDTO requestDTO, Errors errors) {
        userService.checkEmail(requestDTO);

        return ResponseEntity.ok().body(ApiUtils.success(HttpStatus.OK, null));
    }

    // 인증코드 전송
    @PostMapping("/email/code")
    public ResponseEntity<?> sendEmailCode(@RequestBody @Valid UserRequest.SendEmailCodeDTO requestDTO, Errors errors) {
        userService.sendEmailCode(requestDTO);

        return ResponseEntity.ok().body(ApiUtils.success(HttpStatus.OK, null));
    }

    // 인증코드 확인
    @PostMapping("/email/code/check")
    public ResponseEntity<?> checkEmailCode(@RequestBody @Valid UserRequest.CheckEmailCodeDTO requestDTO, Errors errors) {
        UserResponse.CheckEmailCodeDTO responseDTO = userService.checkEmailCode(requestDTO);

        return ResponseEntity.ok().body(ApiUtils.success(HttpStatus.OK, responseDTO));
    }

    // 회원가입
    @PostMapping("/join")
    public ResponseEntity<?> join(@RequestBody @Valid UserRequest.JoinDTO requestDTO, Errors errors) {
        userService.join(requestDTO);

        return ResponseEntity.ok().body(ApiUtils.success(HttpStatus.CREATED, null));
    }

    // 로그인
    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody @Valid UserRequest.LoginDTO requestDTO, Errors errors) {
        UserResponse.TokenDTO responseDTO = userService.login(requestDTO);
        ResponseCookie responseCookie = setRefreshTokenCookie(responseDTO.refreshToken());

        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, responseCookie.toString())
                .body(ApiUtils.success(HttpStatus.OK, new UserResponse.LoginDTO(responseDTO.accessToken())));
    }

    // 비밀번호 재설정
    @PostMapping("/password/change")
    public ResponseEntity<?> changePassword(@RequestBody @Valid UserRequest.ChangePwdDTO requestDTO, Errors errors) {
        userService.changePassword(requestDTO);

        return ResponseEntity.ok().body(ApiUtils.success(HttpStatus.OK, null));
    }

    // 토큰 재발급
    @GetMapping("/refresh")
    public ResponseEntity<?> refresh(@CookieValue String refreshToken) {
        UserResponse.TokenDTO responseDTO = userService.refresh(refreshToken);
        ResponseCookie responseCookie = setRefreshTokenCookie(responseDTO.refreshToken());

        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, responseCookie.toString())
                .body(ApiUtils.success(HttpStatus.OK, new UserResponse.LoginDTO(responseDTO.accessToken())));
    }

    // 사용자 정보 조회하기
    @GetMapping("/users")
    public ResponseEntity<?> findUser(@AuthenticationPrincipal CustomUserDetails userDetails) {
        UserResponse.UserDTO responseDTO = userService.findUser(userDetails.getUser());

        return ResponseEntity.ok().body(responseDTO);
    }
}