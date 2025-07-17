package com.shoppingmall.backend.service;

import com.shoppingmall.backend.dto.LoginRequest;
import com.shoppingmall.backend.dto.SignupRequest;
import com.shoppingmall.backend.entity.Member;
import com.shoppingmall.backend.repository.MemberRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final MemberRepository memberRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtProvider jwtProvider;

    public void signup(SignupRequest request) {
        if (memberRepository.existsByEmail(request.getEmail())) {
            throw new RuntimeException("이미 가입된 이메일입니다.");
        }

        String encodedPw = passwordEncoder.encode(request.getPassword());
        Member member = new Member(request.getEmail(), request.getNickname(), encodedPw);
        memberRepository.save(member);
    }

    public String login(LoginRequest request) {
        Member member = memberRepository.findByEmail(request.getEmail())
                .orElseThrow(() -> new RuntimeException("가입되지 않은 이메일입니다."));

        if (!passwordEncoder.matches(request.getPassword(), member.getPassword())) {
            throw new RuntimeException("비밀번호가 일치하지 않습니다.");
        }

        return jwtProvider.createToken(member.getEmail());
    }
}
