package com.scenarioalert.engine.api;

import com.scenarioalert.engine.attack.AttackService;
import com.scenarioalert.engine.auth.AuthService.User;
import com.scenarioalert.engine.auth.RequireRole;
import com.scenarioalert.engine.common.ApiException;
import com.scenarioalert.engine.common.Json;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RequestPart;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.util.List;
import java.util.Map;

/**
 * MITRE ATT&CK 내부 사본 API. 조회는 viewer, 가져오기·활성화·삭제는 admin.
 * 폐쇄망: 인터넷이 되는 PC 에서 받은 공식 STIX 번들을 화면에서 올리거나 서버의 ATT&CK 디렉터리(ATTACK_DIR)에 복사해 가져온다.
 */
@RestController
@RequestMapping("/api/v1/attack")
public class AttackController {
    private final AttackService attack;

    public AttackController(AttackService attack) {
        this.attack = attack;
    }

    @GetMapping("/versions")
    @RequireRole("viewer")
    public Map<String, Object> versions() {
        return Json.obj("versions", attack.versions(), "active", attack.active());
    }

    @PostMapping("/versions/import")
    @RequireRole("admin")
    public Map<String, Object> upload(@RequestPart("file") MultipartFile file,
                                      @RequestParam(value = "version", required = false) String version, User user) {
        if (file.isEmpty()) {
            throw ApiException.badRequest("빈 파일입니다");
        }
        String name = file.getOriginalFilename() == null ? "upload.json" : file.getOriginalFilename().replaceAll("[^A-Za-z0-9._\\-]", "_");
        try (InputStream in = file.getInputStream()) {
            return attack.importStream(in, name, user.username(), version);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    /** 다른 서버로 옮기기: 버전 하나를 패키지(zip)로 내려받는다. 받는 쪽은 /versions/import-package 로 올리거나 ATTACK_DIR 에 둔다. */
    @GetMapping("/versions/{domain}/{version}/export")
    @RequireRole("admin")
    public ResponseEntity<byte[]> export(@PathVariable String domain, @PathVariable String version, User user) {
        return Downloads.zip(attack.exportPackage(domain, version, user.username()), AttackService.packageName(domain, version));
    }

    @PostMapping("/versions/import-package")
    @RequireRole("admin")
    public Map<String, Object> importPackage(@RequestPart("file") MultipartFile file, User user) {
        if (file.isEmpty()) {
            throw ApiException.badRequest("빈 파일입니다");
        }
        String name = file.getOriginalFilename() == null ? "package.zip" : file.getOriginalFilename().replaceAll("[^A-Za-z0-9._\\-]", "_");
        try (InputStream in = file.getInputStream()) {
            return attack.importPackage(in, name, user.username());
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    @GetMapping("/files")
    @RequireRole("admin")
    public Map<String, Object> files() {
        return Json.obj("dir", attack.dir().toString(), "files", attack.files());
    }

    @PostMapping("/files/import")
    @RequireRole("admin")
    public Map<String, Object> importFile(@RequestBody Map<String, Object> body, User user) {
        return attack.importFile(Body.str(body, "file"), user.username(), Body.optStr(body, "version"));
    }

    @PostMapping("/versions/{domain}/{version}/activate")
    @RequireRole("admin")
    public Map<String, Object> activate(@PathVariable String domain, @PathVariable String version, User user) {
        attack.activate(domain, version, user.username());
        return Json.obj("domain", domain, "version", version, "is_active", true);
    }

    @DeleteMapping("/versions/{domain}/{version}")
    @RequireRole("admin")
    public Map<String, Object> delete(@PathVariable String domain, @PathVariable String version, User user) {
        attack.delete(domain, version, user.username());
        return Json.obj("deleted", true);
    }

    /** from(기본: 활성 버전) → version 비교와 현재 룰·순서도 영향. 활성화 전에 확인한다. */
    @GetMapping("/versions/{domain}/{version}/diff")
    @RequireRole("viewer")
    public Map<String, Object> diff(@PathVariable String domain, @PathVariable String version,
                                    @RequestParam(value = "from", required = false) String from) {
        return attack.diff(domain, version, from);
    }

    @GetMapping("/techniques")
    @RequireRole("viewer")
    public List<Map<String, Object>> search(@RequestParam(value = "q", required = false) String q,
                                            @RequestParam(value = "domain", required = false) String domain,
                                            @RequestParam(value = "version", required = false) String version,
                                            @RequestParam(value = "limit", defaultValue = "30") int limit) {
        return attack.search(q, domain, version, limit);
    }

    @GetMapping("/techniques/{id}")
    @RequireRole("viewer")
    public Map<String, Object> technique(@PathVariable String id, @RequestParam(value = "domain", required = false) String domain,
                                         @RequestParam(value = "version", required = false) String version) {
        return attack.technique(id, domain, version);
    }

    /** 기법 ID 여러 개의 활성 버전 정보 (화면의 칩 표시용). */
    @PostMapping("/techniques/lookup")
    @RequireRole("viewer")
    public Map<String, Map<String, Object>> lookup(@RequestBody Map<String, Object> body) {
        return attack.lookup(AttackService.ids(body.get("ids")));
    }

    @GetMapping("/matrix")
    @RequireRole("viewer")
    public Map<String, Object> matrix(@RequestParam(value = "domain", required = false) String domain,
                                      @RequestParam(value = "version", required = false) String version) {
        return attack.matrix(domain, version);
    }
}
