package com.scenarioalert.engine.api;

import java.util.ArrayList;
import java.util.List;

/** 작은 CSV 해석기 (RFC 4180: 큰따옴표 묶음, "" 이스케이프, 줄바꿈 \n / \r\n). */
final class Csv {
    private Csv() {
    }

    static List<List<String>> parse(String text) {
        List<List<String>> rows = new ArrayList<>();
        List<String> row = new ArrayList<>();
        StringBuilder cell = new StringBuilder();
        boolean quoted = false;
        boolean any = false;
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            if (quoted) {
                if (c == '"') {
                    if (i + 1 < text.length() && text.charAt(i + 1) == '"') {
                        cell.append('"');
                        i++;
                    } else {
                        quoted = false;
                    }
                } else {
                    cell.append(c);
                }
                continue;
            }
            switch (c) {
                case '"' -> {
                    quoted = true;
                    any = true;
                }
                case ',' -> {
                    row.add(cell.toString());
                    cell.setLength(0);
                    any = true;
                }
                case '\r' -> {
                }
                case '\n' -> {
                    row.add(cell.toString());
                    cell.setLength(0);
                    rows.add(row);
                    row = new ArrayList<>();
                    any = false;
                }
                default -> {
                    cell.append(c);
                    any = true;
                }
            }
        }
        if (any || cell.length() > 0 || !row.isEmpty()) {
            row.add(cell.toString());
            rows.add(row);
        }
        return rows;
    }
}
