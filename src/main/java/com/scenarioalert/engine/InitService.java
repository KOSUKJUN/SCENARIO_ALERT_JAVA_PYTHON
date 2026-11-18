package com.scenarioalert.engine;

import com.scenarioalert.engine.attack.AttackService;
import com.scenarioalert.engine.d3fend.D3fendService;
import com.scenarioalert.engine.ch.ClickHouse;
import com.scenarioalert.engine.ch.ClickHouse.Purpose;
import com.scenarioalert.engine.common.Db;
import com.scenarioalert.engine.common.Json;
import com.scenarioalert.engine.common.Kst;
import com.scenarioalert.engine.config.AppProperties;
import com.scenarioalert.engine.repo.Repo;
import com.scenarioalert.engine.sample.SampleDataService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static com.scenarioalert.engine.common.Db.p;

/**
 * 초기화 작업 (Python 원본 server/cli.py 와 같은 순서).
 * init: (Flyway 마이그레이션은 시작 때 끝남) → ClickHouse SQL 파일 적용 → 기준 데이터 → ATT&CK 번들 → 기본 룰 → (SEED_SAMPLE) 샘플 이벤트.
 * 기본 순서도를 넣을 때 순서도마다 Python 평가 코드가 생성된다.
 */
@Component
public class InitService {
    private static final Logger log = LoggerFactory.getLogger(InitService.class);
    static final List<String> CH_DIRS = List.of("source", "tables", "dictionaries", "views");

    private final Db db;
    private final ClickHouse ch;
    private final Repo repo;
    private final SampleDataService samples;
    private final AppProperties props;
    private final AttackService attack;
    private final D3fendService d3fend;

    public InitService(Db db, ClickHouse ch, Repo repo, SampleDataService samples, AppProperties props, AttackService attack,
                       D3fendService d3fend) {
        this.attack = attack;
        this.d3fend = d3fend;
        this.db = db;
        this.ch = ch;
        this.repo = repo;
        this.samples = samples;
        this.props = props;
    }

    Path root() {
        return Path.of(props.rootDir()).toAbsolutePath().normalize();
    }

    public void waitReady(int timeoutSec) {
        long t0 = System.nanoTime();
        while (true) {
            try {
                db.row("SELECT 1 AS x", Map.of());
                ch.query("SELECT 1 AS x", Map.of(), Purpose.ADMIN);
                return;
            } catch (RuntimeException e) {
                if ((System.nanoTime() - t0) / 1e9 > timeoutSec) {
                    throw e;
                }
                log.info("waiting for databases: {}", e.getMessage());
                try {
                    Thread.sleep(2000);
                } catch (InterruptedException ie) {
                    Thread.currentThread().interrupt();
                    throw e;
                }
            }
        }
    }

    static List<String> splitSql(String text) {
        String body = text.lines().filter(l -> !l.strip().startsWith("--")).collect(Collectors.joining("\n"));
        List<String> out = new ArrayList<>();
        for (String s : body.split(";\\s*(?:\\n|$)")) {
            if (!s.isBlank()) {
                out.add(s.strip());
            }
        }
        return out;
    }

    /**
     * 번호 붙은 SQL 파일을 순서대로 적용 (모두 IF NOT EXISTS / OR REPLACE 라 반복 실행해도 된다).
     * source/ 는 테스트 전용 원본 테이블 사본이다. 운영에서는 includeSource=false 로 쓴다.
     */
    public void applyClickHouse(boolean includeSource) {
        List<Path> files = new ArrayList<>();
        for (String d : CH_DIRS) {
            if (d.equals("source") && !includeSource) {
                continue;
            }
            Path dir = root().resolve("clickhouse").resolve(d);
            if (!Files.isDirectory(dir)) {
                continue;
            }
            try (Stream<Path> s = Files.list(dir)) {
                s.filter(f -> f.toString().endsWith(".sql")).forEach(files::add);
            } catch (IOException e) {
                throw new UncheckedIOException(e);
            }
        }
        files.sort(Comparator.comparing(f -> f.getFileName().toString()));
        for (Path f : files) {
            try {
                for (String stmt : splitSql(Files.readString(f, StandardCharsets.UTF_8))) {
                    ch.command(stmt, Map.of(), Purpose.ADMIN);
                }
            } catch (IOException e) {
                throw new UncheckedIOException(e);
            }
            log.info("applied {}", root().relativize(f));
        }
    }

    /** 원본 이벤트 테이블 (운영과 같은 이름·구조. 조회·적재 입구는 Distributed, 실제 데이터는 store). */
    public static final String SOURCE = "default.log_integrated_success_all";
    public static final String SOURCE_STORE = "default.log_integrated_success_store";

    public Map<String, Object> loadBuiltin(String status) {
        int[] n = {0, 0};
        db.txRun(() -> {
            try (Stream<Path> s = Files.list(root().resolve("rules/builtin/single"))) {
                for (Path f : s.filter(x -> x.toString().endsWith(".yaml")).sorted().toList()) {
                    Map<String, Object> d = Json.loadYamlMap(Files.readString(f, StandardCharsets.UTF_8));
                    if (db.row("SELECT 1 AS x FROM single_rules WHERE rule_id=:r", p("r", d.get("id"))) != null) {
                        continue;
                    }
                    repo.saveRule(d, "system", "기본 제공 룰", true, status);
                    n[0]++;
                }
            } catch (IOException e) {
                throw new UncheckedIOException(e);
            }
            try (Stream<Path> s = Files.list(root().resolve("rules/builtin/scenarios"))) {
                for (Path f : s.filter(x -> x.toString().endsWith(".json")).sorted().toList()) {
                    Map<String, Object> g = Json.loadMap(Files.readString(f, StandardCharsets.UTF_8));
                    if (db.row("SELECT 1 AS x FROM scenarios WHERE scenario_id=:s", p("s", g.get("id"))) != null) {
                        continue;
                    }
                    repo.saveScenario(g, "system", "기본 제공 순서도", true, status);  // ← 여기서 Python 코드 생성
                    n[1]++;
                }
            } catch (IOException e) {
                throw new UncheckedIOException(e);
            }
        });
        return Json.obj("rules", n[0], "scenarios", n[1]);
    }

    @SuppressWarnings("unchecked")
    public void loadSample(double hours) {
        LocalDateTime now = Kst.now();
        Map<String, Object> info = samples.loadHistory(now, hours);
        LocalDateTime start = Kst.floor(now.minusSeconds((long) (hours * 3600)), 60);
        samples.seedKnownIncidents((Map<String, String>) info.get("scenarios"));
        // 스케줄러가 샘플 시작 시각부터 따라잡도록 마지막 평가 시각을 되돌린다
        db.txRun(() -> db.execute("UPDATE single_rules SET last_evaluated_to=:s, next_run_at=NULL WHERE status IN "
                + "('silent','active') AND (last_evaluated_to IS NULL OR last_evaluated_to > :s)", p("s", start)));
        log.info("sample loaded: {}", Json.dump(info));
    }

    /** 테스트 데이터 초기화: 이벤트·히트·경보·실행 이력을 지운다 (설정·룰은 유지). 개발 환경 전용. */
    public void resetData() {
        for (String t : List.of(SOURCE_STORE, "detect.rule_hits", "detect.rule_hits_backtest", "detect.peer_first_seen")) {
            ch.command("TRUNCATE TABLE IF EXISTS " + t, Map.of(), Purpose.ADMIN);
        }
        db.txRun(() -> {
            for (String t : List.of("alerts", "rule_runs", "backtest_jobs", "known_incidents")) {
                db.execute("DELETE FROM " + t, Map.of());
            }
            db.execute("UPDATE single_rules SET last_evaluated_to=NULL, next_run_at=NULL, consecutive_failures=0", Map.of());
            // 통합 테스트가 넣은 잘라 낸 ATT&CK 번들(테스트 픽스처). 실제 번들과 버전 번호가 같아 init 의 가져오기를 막는다
            db.execute("DELETE FROM attack_versions WHERE imported_by='test'", Map.of());
            db.execute("DELETE FROM d3fend_versions WHERE imported_by='test'", Map.of());
        });
        log.info("data reset");
    }

    public void init() {
        waitReady(120);
        applyClickHouse(true);
        samples.seedReference();
        // ATT&CK 번들(ATTACK_DIR)을 기본 룰보다 먼저 가져온다: 룰의 기법 참조를 활성 버전으로 검사한다
        log.info("ATT&CK: {}", attack.importDir("system"));
        // D3FEND 릴리스(D3FEND_DIR/<버전>/)도 기본 룰보다 먼저: 룰·경보 노드의 지정 대응방책을 활성 버전으로 검사한다
        log.info("D3FEND: {}", d3fend.importDir("system"));
        log.info("builtin loaded: {}", loadBuiltin(props.init().builtinStatus()));
        ch.reloadDictionaries();
        if (props.init().seedSample()) {
            List<Map<String, Object>> r = ch.query("SELECT count() AS n FROM " + SOURCE, Map.of(), Purpose.ADMIN);
            long n = r.isEmpty() ? 0 : (long) ClickHouse.num(r.get(0), "n");
            if (n == 0) {
                loadSample(props.init().sampleHours());
            } else {
                log.info("sample events already present ({} rows) - skip", n);
            }
        }
    }
}
