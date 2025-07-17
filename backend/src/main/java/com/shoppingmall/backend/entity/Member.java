package com.shoppingmall.backend.entity;

import jakarta.persistence.*;
import lombok.Data;
import lombok.NoArgsConstructor;

@Entity
@Data
@NoArgsConstructor
public class Member {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true)
    private String email;

    @Column(nullable = true)
    private String password;

    @Column(nullable = false)
    private String nickname;

    // 소셜 회원가입 생성자
    public Member(String email, String nickname) {
        this.email = email;
        this.nickname = nickname;
    }

    // 일반 회원가입 생성자
    public Member(String email, String nickname, String password) {
        this.email = email;
        this.nickname = nickname;
        this.password = password;
    }

    // ✅ 비밀번호 변경을 위한 Setter 명시
    public void setPassword(String password) {
        this.password = password;
    }
}
