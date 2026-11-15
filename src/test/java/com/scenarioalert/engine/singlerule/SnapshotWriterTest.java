package com.scenarioalert.engine.singlerule;

import com.scenarioalert.engine.TestFiles;
import com.scenarioalert.engine.singlerule.RuleCompiler.CompiledRule;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * 새 기본 룰의 컴파일 스냅샷을 만든다. 기존 스냅샷(Python 원본과 같아야 하는 것)은 절대 덮어쓰지 않는다.
 * 실행: mvn test -Dtest=SnapshotWriterTest -Dsnapshots.write=true
 * 만든 파일은 사람이 검토한 뒤 커밋한다 (RuleCompilerTest 가 이후 변경을 잡는다).
 */
class SnapshotWriterTest {
    @Test
    void writeMissingSnapshots() throws IOException {
        Assumptions.assumeTrue(Boolean.getBoolean("snapshots.write"), "-Dsnapshots.write=true 일 때만");
        for (Path p : TestFiles.builtinRules()) {
            Path snap = Path.of("src/test/resources/snapshots/" + TestFiles.stem(p) + ".sql");
            if (Files.exists(snap)) {
                continue;
            }
            CompiledRule c = RuleCompiler.compileRealtime(RuleCompilerTest.parsed(p), RuleCompilerTest.LOADER);
            Files.writeString(snap, RuleCompilerTest.snapshotText(c));
            System.out.println("snapshot written: " + snap);
        }
    }
}
