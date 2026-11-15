package com.scenarioalert.engine.common;

import java.math.BigInteger;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.regex.Pattern;

/**
 * IP·CIDR 검증과 정규화 (Python ipaddress 와 같은 결과). DNS 조회를 하지 않는다.
 */
public final class Ip {
    private static final Pattern V4 = Pattern.compile("^(25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)(\\.(25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)){3}$");
    private static final Pattern V6_CHARS = Pattern.compile("^[0-9A-Fa-f:.]+$");

    private Ip() {
    }

    /** 정규화한 IP 문자열. 형식이 아니면 null. */
    public static String normalize(String v) {
        if (v == null) {
            return null;
        }
        String s = v.trim();
        if (V4.matcher(s).matches()) {
            return s;
        }
        if (s.contains(":") && V6_CHARS.matcher(s).matches()) {
            byte[] b = v6Bytes(s);
            return b == null ? null : formatV6(b);
        }
        return null;
    }

    /** strict=False 와 같이 호스트 비트를 지운 "네트워크/길이". 형식이 아니면 null. */
    public static String normalizeCidr(String v) {
        if (v == null) {
            return null;
        }
        String s = v.trim();
        String addr = s;
        Integer prefix = null;
        int slash = s.indexOf('/');
        if (slash >= 0) {
            addr = s.substring(0, slash);
            String p = s.substring(slash + 1);
            if (!p.matches("\\d{1,3}")) {
                return null;
            }
            prefix = Integer.parseInt(p);
        }
        if (V4.matcher(addr).matches()) {
            int pf = prefix == null ? 32 : prefix;
            if (pf > 32) {
                return null;
            }
            long n = 0;
            for (String o : addr.split("\\.")) {
                n = (n << 8) | Integer.parseInt(o);
            }
            long mask = pf == 0 ? 0 : (0xFFFFFFFFL << (32 - pf)) & 0xFFFFFFFFL;
            n &= mask;
            return ((n >> 24) & 255) + "." + ((n >> 16) & 255) + "." + ((n >> 8) & 255) + "." + (n & 255) + "/" + pf;
        }
        if (addr.contains(":") && V6_CHARS.matcher(addr).matches()) {
            byte[] b = v6Bytes(addr);
            int pf = prefix == null ? 128 : prefix;
            if (b == null || pf > 128) {
                return null;
            }
            BigInteger n = new BigInteger(1, b);
            BigInteger mask = pf == 0 ? BigInteger.ZERO
                    : BigInteger.ONE.shiftLeft(128).subtract(BigInteger.ONE).shiftRight(128 - pf).shiftLeft(128 - pf);
            byte[] raw = n.and(mask).toByteArray();
            byte[] out = new byte[16];
            int copy = Math.min(16, raw.length);
            System.arraycopy(raw, raw.length - copy, out, 16 - copy, copy);
            return formatV6(out) + "/" + pf;
        }
        return null;
    }

    public static boolean isIp(String v) {
        return normalize(v) != null;
    }

    private static byte[] v6Bytes(String s) {
        try {
            InetAddress a = InetAddress.getByName(s);  // 리터럴이라 조회 없음
            byte[] b = a.getAddress();
            if (b.length == 4) {  // ::ffff:a.b.c.d 는 Java 가 IPv4 로 돌려준다
                byte[] out = new byte[16];
                out[10] = (byte) 0xff;
                out[11] = (byte) 0xff;
                System.arraycopy(b, 0, out, 12, 4);
                return out;
            }
            return a instanceof Inet6Address ? b : null;
        } catch (UnknownHostException | SecurityException e) {
            return null;
        }
    }

    /** RFC 5952 압축 표기 (가장 긴 0 연속을 ::). */
    private static String formatV6(byte[] b) {
        int[] w = new int[8];
        for (int i = 0; i < 8; i++) {
            w[i] = ((b[2 * i] & 255) << 8) | (b[2 * i + 1] & 255);
        }
        int bestStart = -1;
        int bestLen = 0;
        for (int i = 0; i < 8; ) {
            if (w[i] == 0) {
                int j = i;
                while (j < 8 && w[j] == 0) {
                    j++;
                }
                if (j - i > bestLen && j - i >= 2) {
                    bestStart = i;
                    bestLen = j - i;
                }
                i = j;
            } else {
                i++;
            }
        }
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 8; i++) {
            if (i == bestStart) {
                sb.append("::");
                i += bestLen - 1;
                continue;
            }
            if (sb.length() > 0 && sb.charAt(sb.length() - 1) != ':') {
                sb.append(':');
            }
            sb.append(Integer.toHexString(w[i]));
        }
        return sb.toString();
    }
}
