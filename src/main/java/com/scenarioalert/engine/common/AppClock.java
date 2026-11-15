package com.scenarioalert.engine.common;

import java.time.LocalDateTime;

/** 시계 주입 (CLAUDE.md: 시간에 의존하는 코드는 시계를 주입받는다). */
@FunctionalInterface
public interface AppClock {
    LocalDateTime now();

    AppClock SYSTEM = Kst::now;

    /** 테스트용 고정 시계. */
    final class Fixed implements AppClock {
        private volatile LocalDateTime t;

        public Fixed(LocalDateTime t) {
            this.t = t;
        }

        @Override
        public LocalDateTime now() {
            return t;
        }

        public void set(LocalDateTime t) {
            this.t = t;
        }

        public void advance(long seconds) {
            this.t = t.plusSeconds(seconds);
        }
    }
}
