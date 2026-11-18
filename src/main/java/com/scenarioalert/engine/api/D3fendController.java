package com.scenarioalert.engine.api;

import com.scenarioalert.engine.attack.AttackService;
import com.scenarioalert.engine.auth.AuthService.User;
import com.scenarioalert.engine.auth.RequireRole;
import com.scenarioalert.engine.common.ApiException;
import com.scenarioalert.engine.common.Json;
import com.scenarioalert.engine.d3fend.D3fendService;
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
 * MITRE D3FEND 내부 사본 API. 조회는 viewer, 가져오기·활성화·삭제는 admin.
 * 폐쇄망: 인터넷이 되는 PC 에서 받은 공식 릴리스(d3fend.json + d3fend-full-mappings.csv)를 화면에서 올리거나
 * 서버의 D3FEND 디렉터리(D3FEND_DIR/&lt;버전&gt;/)에 복사해 가져온다.
 */
@RestController
@RequestMapping("/api/v1/d3fend")
public class D3fendController {
    private final D3fendService d3fend;

    public D3fendController(D3fendService d3fend) {
        this.d3fend = d3fend;
    }

    @GetMapping("/versions")
    @RequireRole("viewer")
    public Map<String, Object> versions() {
        return Json.obj("versions", d3fend.versions(), "active", d3fend.active());
    }

    @PostMapping("/versions/import")
    @RequireRole("admin")
    public Map<String, Object> upload(@RequestPart("ontology") MultipartFile ontology, @RequestPart("mappings") MultipartFile mappings,
                                      @RequestParam(value = "version", required = false) String version, User user) {
        if (ontology.isEmpty() || mappings.isEmpty()) {
            throw ApiException.badRequest("온톨로지(d3fend.json)와 매핑(d3fend-full-mappings.csv) 파일이 모두 필요합니다");
        }
        try (InputStream o = ontology.getInputStream(); InputStream m = mappings.getInputStream()) {
            return d3fend.importStreams(o, safe(ontology.getOriginalFilename(), D3fendService.ONTOLOGY_FILE), m,
                    safe(mappings.getOriginalFilename(), D3fendService.MAPPINGS_FILE), "upload", user.username(), version);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    private static String safe(String name, String fallback) {
        return name == null || name.isBlank() ? fallback : name.replaceAll("[^A-Za-z0-9._\\-]", "_");
    }

    @GetMapping("/files")
    @RequireRole("admin")
    public Map<String, Object> files() {
        return Json.obj("dir", d3fend.dir().toString(), "files", d3fend.files());
    }

    @PostMapping("/files/import")
    @RequireRole("admin")
    public Map<String, Object> importDir(@RequestBody Map<String, Object> body, User user) {
        return d3fend.importDirEntry(Body.str(body, "name"), user.username(), Body.optStr(body, "version"));
    }

    @PostMapping("/versions/{version}/activate")
    @RequireRole("admin")
    public Map<String, Object> activate(@PathVariable String version, User user) {
        d3fend.activate(version, user.username());
        return Json.obj("version", version, "is_active", true);
    }

    @DeleteMapping("/versions/{version}")
    @RequireRole("admin")
    public Map<String, Object> delete(@PathVariable String version, User user) {
        d3fend.delete(version, user.username());
        return Json.obj("deleted", true);
    }

    @GetMapping("/versions/{version}/diff")
    @RequireRole("viewer")
    public Map<String, Object> diff(@PathVariable String version, @RequestParam(value = "from", required = false) String from) {
        return d3fend.diff(version, from);
    }

    @GetMapping("/techniques")
    @RequireRole("viewer")
    public List<Map<String, Object>> search(@RequestParam(value = "q", required = false) String q,
                                            @RequestParam(value = "version", required = false) String version,
                                            @RequestParam(value = "tactic", required = false) String tactic,
                                            @RequestParam(value = "limit", defaultValue = "30") int limit) {
        return d3fend.search(q, version, tactic, limit);
    }

    @GetMapping("/techniques/{id}")
    @RequireRole("viewer")
    public Map<String, Object> technique(@PathVariable String id, @RequestParam(value = "version", required = false) String version) {
        return d3fend.technique(id, version);
    }

    @PostMapping("/techniques/lookup")
    @RequireRole("viewer")
    public Map<String, Map<String, Object>> lookup(@RequestBody Map<String, Object> body) {
        return d3fend.lookup(D3fendService.ids(body.get("ids")));
    }

    @GetMapping("/matrix")
    @RequireRole("viewer")
    public Map<String, Object> matrix(@RequestParam(value = "version", required = false) String version) {
        return d3fend.matrix(version);
    }

    /** ATT&CK 기법(attack)과 지정 대응 기법(d3fend)에 대한 대응방책: 전술별 지정·권고, ATT&CK 완화(M) 연계. */
    @PostMapping("/countermeasures")
    @RequireRole("viewer")
    public Map<String, Object> countermeasures(@RequestBody Map<String, Object> body) {
        List<String> atk = AttackService.ids(body.get("attack"));
        if (atk.size() > 50) {
            throw ApiException.badRequest("ATT&CK 기법은 50개 이하입니다");
        }
        return d3fend.countermeasures(atk, D3fendService.ids(body.get("d3fend")), Body.optStr(body, "version"));
    }

    /** 단일룰·순서도 경보 노드의 ATT&CK 기법과 지정 대응방책 연계 현황. */
    @GetMapping("/links")
    @RequireRole("viewer")
    public Map<String, Object> links() {
        return d3fend.linkReport();
    }
}
