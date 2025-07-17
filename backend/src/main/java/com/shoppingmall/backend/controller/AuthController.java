package com.shoppingmall.backend.controller;

import com.shoppingmall.backend.dto.LoginRequest;
import com.shoppingmall.backend.dto.SignupRequest;
import com.shoppingmall.backend.entity.Member;
import com.shoppingmall.backend.repository.MemberRepository;
import com.shoppingmall.backend.service.AuthService;
import com.shoppingmall.backend.service.JwtProvider;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;
    private final MemberRepository memberRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtProvider jwtProvider;
    private final JavaMailSender mailSender;

    private static class ResetTokenInfo {
        String email;
        Instant createdAt;

        ResetTokenInfo(String email, Instant createdAt) {
            this.email = email;
            this.createdAt = createdAt;
        }
    }

    private final Map<String, ResetTokenInfo> resetTokens = new ConcurrentHashMap<>();

    @PostMapping("/signup")
    public ResponseEntity<?> signup(@RequestBody SignupRequest request) {
        try {
            authService.signup(request);
            return ResponseEntity.ok("회원가입 성공!");
        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.badRequest().body(e.getMessage());
        }
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginRequest request) {
        String jwt = authService.login(request);
        return ResponseEntity.ok(jwt);
    }

    @PostMapping("/change-password")
    public ResponseEntity<?> changePassword(
            @RequestHeader("Authorization") String authHeader,
            @RequestBody Map<String, String> passwords) {

        String token = authHeader.replace("Bearer ", "");
        String email = jwtProvider.getClaims(token).getSubject();

        Member member = memberRepository.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("유저를 찾을 수 없습니다."));

        String currentPassword = passwords.get("currentPassword");
        String newPassword = passwords.get("newPassword");

        if (!passwordEncoder.matches(currentPassword, member.getPassword())) {
            return ResponseEntity.badRequest().body("현재 비밀번호가 일치하지 않습니다.");
        }

        member.setPassword(passwordEncoder.encode(newPassword));
        memberRepository.save(member);

        return ResponseEntity.ok("비밀번호 변경 완료!");
    }

    @PostMapping("/request-reset")
    public ResponseEntity<?> requestPasswordReset(@RequestBody Map<String, String> body) {
        String email = body.get("email");

        Optional<Member> memberOpt = memberRepository.findByEmail(email);
        if (memberOpt.isEmpty()) {
            return ResponseEntity.badRequest().body("해당 이메일로 가입된 사용자가 없습니다.");
        }

        String token = UUID.randomUUID().toString();
        resetTokens.put(token, new ResetTokenInfo(email, Instant.now()));

        String resetLink = "http://localhost:3000/reset-password?token=" + token;

        // ✅ 이메일 전송
        SimpleMailMessage message = new SimpleMailMessage();
        message.setTo(email);
        message.setSubject("[Trendy Mall] 비밀번호 재설정 안내");
        message.setText("안녕하세요.\n\n아래 링크를 클릭하여 비밀번호를 재설정해주세요.\n\n" + resetLink + "\n\n이 링크는 15분 동안만 유효합니다.");

        mailSender.send(message);

        return ResponseEntity.ok("비밀번호 재설정 링크를 이메일로 발송했습니다.");
    }

    @PostMapping("/reset-password")
    public ResponseEntity<?> resetPassword(@RequestBody Map<String, String> body) {
        String token = body.get("token");
        String newPassword = body.get("newPassword");

        ResetTokenInfo info = resetTokens.get(token);
        if (info == null) {
            return ResponseEntity.badRequest().body("유효하지 않은 또는 만료된 토큰입니다.");
        }

        if (Duration.between(info.createdAt, Instant.now()).toMinutes() > 15) {
            resetTokens.remove(token);
            return ResponseEntity.badRequest().body("토큰이 만료되었습니다. 다시 요청해주세요.");
        }

        Member member = memberRepository.findByEmail(info.email)
                .orElseThrow(() -> new RuntimeException("사용자를 찾을 수 없습니다."));

        member.setPassword(passwordEncoder.encode(newPassword));
        memberRepository.save(member);
        resetTokens.remove(token);

        return ResponseEntity.ok("비밀번호가 성공적으로 변경되었습니다.");
    }
}
