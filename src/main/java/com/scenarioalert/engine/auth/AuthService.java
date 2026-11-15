package com.scenarioalert.engine.auth;

import com.scenarioalert.engine.common.ApiException;
import com.scenarioalert.engine.common.AppClock;
import com.scenarioalert.engine.common.Db;
import com.scenarioalert.engine.config.AppProperties;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;

import static com.scenarioalert.engine.common.Db.p;

/**
 * 세션 토큰 인증과 역할 기반 권한. 비밀번호는 PBKDF2-SHA256 200,000회 ("pbkdf2$salt$hex", Python 원본과 같은 형식).
 */
@Component
public class AuthService {
    public static final List<String> ROLES = List.of("viewer", "analyst", "author", "admin");
    private static final SecureRandom RNG = new SecureRandom();

    private final Db db;
    private final AppProperties props;
    private final AppClock clock = AppClock.SYSTEM;

    public AuthService(Db db, AppProperties props) {
        this.db = db;
        this.props = props;
    }

    public record User(String username, String role) {
        public boolean has(String need) {
            return ROLES.indexOf(role) >= ROLES.indexOf(need);
        }
    }

    public static String hashPassword(String pw, String salt) {
        String s = salt != null ? salt : HexFormat.of().formatHex(randomBytes(8));
        try {
            SecretKeyFactory f = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            byte[] dk = f.generateSecret(new PBEKeySpec(pw.toCharArray(), s.getBytes(StandardCharsets.UTF_8), 200_000, 256))
                    .getEncoded();
            return "pbkdf2$" + s + "$" + HexFormat.of().formatHex(dk);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    public static String hashPassword(String pw) {
        return hashPassword(pw, null);
    }

    public static boolean verifyPassword(String pw, String stored) {
        String[] parts = stored == null ? new String[0] : stored.split("\\$");
        if (parts.length != 3) {
            return false;
        }
        return MessageDigest.isEqual(hashPassword(pw, parts[1]).getBytes(StandardCharsets.UTF_8),
                stored.getBytes(StandardCharsets.UTF_8));
    }

    private static byte[] randomBytes(int n) {
        byte[] b = new byte[n];
        RNG.nextBytes(b);
        return b;
    }

    public Map<String, Object> login(String username, String password) {
        Map<String, Object> u = db.row("SELECT username, password_hash, role, enabled FROM users WHERE username=:u",
                p("u", username));
        if (u == null || !Db.bool(u, "enabled") || !verifyPassword(password, Db.str(u, "password_hash"))) {
            throw new ApiException(401, "아이디 또는 비밀번호가 올바르지 않습니다");
        }
        String token = HexFormat.of().formatHex(randomBytes(24));
        db.execute("INSERT INTO sessions (token, username, expires_at) VALUES (:t, :u, :e)",
                p("t", token, "u", username, "e", clock.now().plusHours(props.sessionHours())));
        return Map.of("token", token, "username", Db.str(u, "username"), "role", Db.str(u, "role"));
    }

    public User authenticate(String authorization) {
        if (authorization == null || !authorization.toLowerCase().startsWith("bearer ")) {
            throw new ApiException(401, "로그인이 필요합니다");
        }
        String token = authorization.substring(7).trim();
        Map<String, Object> r = db.row("SELECT u.username, u.role FROM sessions s JOIN users u ON u.username = s.username "
                + "WHERE s.token=:t AND s.expires_at > :now AND u.enabled=1", p("t", token, "now", clock.now()));
        if (r == null) {
            throw new ApiException(401, "세션이 만료되었습니다. 다시 로그인하세요");
        }
        return new User(Db.str(r, "username"), Db.str(r, "role"));
    }

    public void checkServiceToken(String authorization) {
        String tok = props.caseSystem().serviceToken();
        if (tok == null || tok.isEmpty() || authorization == null
                || !MessageDigest.isEqual(authorization.getBytes(StandardCharsets.UTF_8),
                ("Bearer " + tok).getBytes(StandardCharsets.UTF_8))) {
            throw new ApiException(401, "서비스 토큰이 올바르지 않습니다");
        }
    }
}
