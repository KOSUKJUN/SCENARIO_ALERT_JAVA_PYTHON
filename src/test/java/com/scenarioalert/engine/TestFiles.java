package com.scenarioalert.engine;

import com.scenarioalert.engine.common.Json;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

/** 테스트용 저장소 파일 읽기 (Maven 은 프로젝트 루트에서 테스트를 돈다). */
public final class TestFiles {
    public static final Path ROOT = Path.of(System.getProperty("user.dir")).toAbsolutePath();

    private TestFiles() {
    }

    public static List<Path> list(String dir, String ext) {
        try (Stream<Path> s = Files.list(ROOT.resolve(dir))) {
            return s.filter(p -> p.toString().endsWith(ext)).sorted().toList();
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    public static String read(Path p) {
        try {
            return Files.readString(p, StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    public static List<Path> builtinRules() {
        return list("rules/builtin/single", ".yaml");
    }

    public static List<Path> builtinScenarios() {
        return list("rules/builtin/scenarios", ".json");
    }

    public static Map<String, Object> yaml(Path p) {
        return Json.loadYamlMap(read(p));
    }

    public static Map<String, Object> json(Path p) {
        return Json.loadMap(read(p));
    }

    public static Map<String, Object> scenario(String id) {
        return json(ROOT.resolve("rules/builtin/scenarios/" + id + ".json"));
    }

    public static String stem(Path p) {
        String n = p.getFileName().toString();
        return n.substring(0, n.lastIndexOf('.'));
    }
}
