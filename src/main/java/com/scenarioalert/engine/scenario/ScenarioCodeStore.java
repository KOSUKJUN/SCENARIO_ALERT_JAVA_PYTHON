package com.scenarioalert.engine.scenario;

import com.scenarioalert.engine.config.AppProperties;
import com.scenarioalert.engine.scenario.EvalModels.ScenarioProgram;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;

/**
 * 생성된 시나리오 코드를 파일로 둔다. 원본은 MariaDB(scenario_versions.python_code)이고 파일은 캐시다.
 * 서버가 여러 대여도 각자 DB 에서 같은 내용(같은 sha256)을 만들어 쓰므로 공유 디스크가 필요 없다.
 *
 * <pre>
 *   {codeDir}/SC_SMB_WORM/v3.py       저장된 버전
 *   {codeDir}/_drafts/&lt;sha256&gt;.py     화면 시뮬레이션용 초안 (저장 전)
 * </pre>
 */
@Component
public class ScenarioCodeStore {
    private final Path root;

    public ScenarioCodeStore(AppProperties props) {
        this.root = Path.of(props.python().codeDir()).toAbsolutePath().normalize();
    }

    public Path root() {
        return root;
    }

    public Path pathFor(ScenarioProgram p) {
        if (p.draft()) {
            return root.resolve("_drafts").resolve(p.sha256() + ".py");
        }
        // scenario_id 는 ^[A-Z][A-Z0-9_]{2,63}$ 로 검증된 값이라 경로 조작이 없다
        return root.resolve(p.scenarioId()).resolve("v" + p.version() + ".py");
    }

    /** 파일이 없거나 내용이 다르면 (다시) 쓴다. */
    public Path ensure(ScenarioProgram p) {
        Path path = pathFor(p);
        try {
            if (Files.isRegularFile(path)
                    && ScenarioCodeGenerator.sha256(Files.readString(path, StandardCharsets.UTF_8)).equals(p.sha256())) {
                return path;
            }
            Files.createDirectories(path.getParent());
            Path tmp = Files.createTempFile(path.getParent(), ".gen-", ".tmp");
            Files.writeString(tmp, p.code(), StandardCharsets.UTF_8);
            try {
                Files.move(tmp, path, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
            } catch (AtomicMoveNotSupportedException e) {
                Files.move(tmp, path, StandardCopyOption.REPLACE_EXISTING);
            }
            return path;
        } catch (IOException e) {
            throw new UncheckedIOException("시나리오 코드 파일을 쓸 수 없습니다: " + path, e);
        }
    }
}
