package com.scenarioalert.engine.scenario;

import com.fasterxml.jackson.core.type.TypeReference;
import com.scenarioalert.engine.common.Json;
import com.scenarioalert.engine.config.AppProperties;
import com.scenarioalert.engine.scenario.EvalModels.EvalCase;
import com.scenarioalert.engine.scenario.EvalModels.EvalOutcome;
import com.scenarioalert.engine.scenario.EvalModels.ScenarioProgram;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Timer;
import jakarta.annotation.PreDestroy;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

/**
 * 시나리오별 Python 코드를 실행하는 상주 프로세스 풀.
 *
 * <ul>
 * <li>프로세스: {@code python -I -u python/scenario_runtime/worker.py} (격리 모드, 표준 입출력 JSON 한 줄씩)</li>
 * <li>요청마다 생성 코드 파일 경로와 sha256 을 보낸다. worker 는 (경로, 해시)로 모듈을 캐시하고, 해시가 다르면 거부한다.</li>
 * <li>응답이 제한 시간 안에 오지 않거나 프로세스가 죽으면 그 프로세스를 버리고 새로 띄운다.</li>
 * <li>평가 자체는 상태가 없으므로 프로세스가 바뀌어도 결과가 같다 (서버는 메모리 상태를 갖지 않는다).</li>
 * </ul>
 */
@Component
public class PythonScenarioEngine {
    private static final Logger log = LoggerFactory.getLogger(PythonScenarioEngine.class);
    private static final TypeReference<LinkedHashMap<String, Object>> MAP_T = new TypeReference<>() {
    };
    static final int CASES_PER_REQUEST = 200;

    private final AppProperties.Python cfg;
    private final ScenarioCodeStore store;
    private final BlockingQueue<Worker> idle;
    private final AtomicInteger created = new AtomicInteger();
    private final AtomicLong seq = new AtomicLong();
    private final Timer evalTimer;
    private volatile boolean closed;

    /** Python 을 쓸 수 없거나 생성 코드 실행이 실패했을 때. */
    public static class ScenarioEngineException extends RuntimeException {
        public ScenarioEngineException(String msg) {
            super(msg);
        }

        public ScenarioEngineException(String msg, Throwable cause) {
            super(msg, cause);
        }
    }

    public PythonScenarioEngine(AppProperties props, ScenarioCodeStore store, MeterRegistry meters) {
        this.cfg = props.python();
        this.store = store;
        this.idle = new ArrayBlockingQueue<>(Math.max(1, cfg.workers()));
        this.evalTimer = Timer.builder("scenario_python_eval_seconds").description("시나리오 Python 평가 요청 시간")
                .register(meters);
    }

    // ---------------------------------------------------------------- 공개 API
    /** 같은 시나리오 코드로 여러 대상을 평가한다. 결과는 cases 와 같은 순서. */
    public List<EvalOutcome> evaluate(ScenarioProgram program, List<EvalCase> cases) {
        if (cases.isEmpty()) {
            return List.of();
        }
        Path module = store.ensure(program);
        List<EvalOutcome> out = new ArrayList<>(cases.size());
        for (int i = 0; i < cases.size(); i += CASES_PER_REQUEST) {
            List<EvalCase> chunk = cases.subList(i, Math.min(cases.size(), i + CASES_PER_REQUEST));
            Map<String, Object> req = new LinkedHashMap<>();
            req.put("op", "evaluate");
            req.put("module", module.toString());
            req.put("sha256", program.sha256());
            req.put("cases", chunk.stream().map(EvalCase::toJson).toList());
            Map<String, Object> resp = evalTimer.record(() -> call(req));
            List<Object> results = Json.asList(resp.get("results"));
            if (results == null || results.size() != chunk.size()) {
                throw new ScenarioEngineException("Python 응답 형식이 올바르지 않습니다");
            }
            for (Object r : results) {
                out.add(EvalOutcome.fromJson(Json.asMap(r)));
            }
        }
        return out;
    }

    public EvalOutcome evaluateOne(ScenarioProgram program, EvalCase c) {
        return evaluate(program, List.of(c)).get(0);
    }

    /** 상태 점검: Python 버전 또는 오류. */
    public Map<String, Object> ping() {
        Map<String, Object> req = new LinkedHashMap<>();
        req.put("op", "ping");
        return call(req);
    }

    // ---------------------------------------------------------------- 요청
    private Map<String, Object> call(Map<String, Object> req) {
        if (closed) {
            throw new ScenarioEngineException("시나리오 엔진이 종료되었습니다");
        }
        long id = seq.incrementAndGet();
        req.put("id", id);
        String line = Json.dump(req);
        Worker w = borrow();
        boolean healthy = false;
        try {
            Map<String, Object> resp = w.request(line, id, cfg.timeoutSec());
            healthy = true;
            if (!Boolean.TRUE.equals(resp.get("ok"))) {
                throw new ScenarioEngineException("시나리오 코드 실행 오류: " + resp.get("error"));
            }
            return resp;
        } finally {
            release(w, healthy);
        }
    }

    private Worker borrow() {
        Worker w = idle.poll();
        if (w != null && w.alive()) {
            return w;
        }
        if (w != null) {
            w.destroy();
            created.decrementAndGet();
        }
        if (created.incrementAndGet() <= Math.max(1, cfg.workers())) {
            try {
                return spawn();
            } catch (RuntimeException e) {
                created.decrementAndGet();
                throw e;
            }
        }
        created.decrementAndGet();
        try {
            Worker got = idle.poll(cfg.timeoutSec() * 2L, TimeUnit.SECONDS);
            if (got == null) {
                throw new ScenarioEngineException("Python 평가 프로세스가 모두 사용 중입니다");
            }
            if (!got.alive()) {
                got.destroy();
                return spawn();
            }
            return got;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new ScenarioEngineException("대기 중 중단되었습니다");
        }
    }

    private void release(Worker w, boolean healthy) {
        if (healthy && w.alive() && !closed && idle.offer(w)) {
            return;
        }
        w.destroy();
        created.decrementAndGet();
    }

    private Worker spawn() {
        Path workerPy = Path.of(cfg.runtimeDir()).toAbsolutePath().normalize().resolve("scenario_runtime").resolve("worker.py");
        if (!Files.isRegularFile(workerPy)) {
            throw new ScenarioEngineException("Python 런타임이 없습니다: " + workerPy);
        }
        ProcessBuilder pb = new ProcessBuilder(cfg.executable(), "-I", "-B", "-u", workerPy.toString());
        pb.directory(store.root().toFile().exists() ? store.root().toFile() : null);
        try {
            Worker w = new Worker(pb.start());
            log.info("python scenario worker started (pid {})", w.proc.pid());
            return w;
        } catch (IOException e) {
            throw new ScenarioEngineException("Python 을 실행할 수 없습니다 (" + cfg.executable() + "): " + e.getMessage(), e);
        }
    }

    @PreDestroy
    public void close() {
        closed = true;
        Worker w;
        while ((w = idle.poll()) != null) {
            w.destroy();
        }
    }

    // ---------------------------------------------------------------- 프로세스 하나
    private static final class Worker {
        final Process proc;
        final BufferedWriter in;
        final BlockingQueue<String> lines = new LinkedBlockingQueue<>();

        Worker(Process proc) {
            this.proc = proc;
            this.in = new BufferedWriter(new OutputStreamWriter(proc.getOutputStream(), StandardCharsets.UTF_8));
            Thread out = new Thread(() -> pump(new BufferedReader(new InputStreamReader(proc.getInputStream(),
                    StandardCharsets.UTF_8)), true), "py-out-" + proc.pid());
            Thread err = new Thread(() -> pump(new BufferedReader(new InputStreamReader(proc.getErrorStream(),
                    StandardCharsets.UTF_8)), false), "py-err-" + proc.pid());
            out.setDaemon(true);
            err.setDaemon(true);
            out.start();
            err.start();
        }

        private void pump(BufferedReader r, boolean stdout) {
            try {
                String l;
                while ((l = r.readLine()) != null) {
                    if (stdout) {
                        lines.add(l);
                    } else {
                        log.warn("[python {}] {}", proc.pid(), l);
                    }
                }
            } catch (IOException ignored) {
                // 프로세스 종료
            }
        }

        boolean alive() {
            return proc.isAlive();
        }

        Map<String, Object> request(String line, long id, int timeoutSec) {
            try {
                in.write(line);
                in.write('\n');
                in.flush();
                long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(timeoutSec);
                while (true) {
                    long left = deadline - System.nanoTime();
                    String resp = left > 0 ? lines.poll(left, TimeUnit.NANOSECONDS) : null;
                    if (resp == null) {
                        throw new ScenarioEngineException(proc.isAlive()
                                ? "Python 평가가 " + timeoutSec + "초 안에 끝나지 않았습니다"
                                : "Python 평가 프로세스가 종료되었습니다 (exit " + proc.exitValue() + ")");
                    }
                    Map<String, Object> m = Json.MAPPER.readValue(resp, MAP_T);
                    Object rid = m.get("id");
                    if (rid instanceof Number n && n.longValue() == id) {
                        return m;
                    }
                    // 이전 요청(시간 초과)의 늦은 응답은 버린다
                }
            } catch (IOException e) {
                throw new ScenarioEngineException("Python 평가 프로세스와 통신 실패: " + e.getMessage(), e);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new ScenarioEngineException("Python 평가 대기 중 중단되었습니다");
            }
        }

        void destroy() {
            try {
                in.close();
            } catch (IOException ignored) {
                // 무시
            }
            proc.destroy();
            try {
                if (!proc.waitFor(2, TimeUnit.SECONDS)) {
                    proc.destroyForcibly();
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                proc.destroyForcibly();
            }
        }
    }
}
