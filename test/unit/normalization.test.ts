import { describe, expect, it } from "vitest";
import {
  canonicalHost,
  cidrContains,
  classifyIp,
  ipEquals,
  ipInCidrList,
  isValidHostname,
  parseCidr,
  parseIp,
  parseUrl,
  publicSuffix,
  registrableDomain,
  tryParseUrl,
  unwrapIpv4Mapped,
} from "@reconnexus/normalization";

describe("IP parsing", () => {
  it("parses and canonicalizes IPv4", () => {
    const ip = parseIp("192.168.001.1".replace("001", "1"));
    expect(ip?.version).toBe(4);
    expect(ip?.canonical).toBe("192.168.1.1");
  });

  it("rejects malformed IPv4", () => {
    expect(parseIp("256.1.1.1")).toBeNull();
    expect(parseIp("1.2.3")).toBeNull();
    expect(parseIp("01.2.3.4")).toBeNull();
  });

  it("parses compressed IPv6", () => {
    expect(parseIp("2001:db8::1")?.canonical).toBe("2001:db8::1");
    expect(parseIp("::1")?.canonical).toBe("::1");
  });

  it("unwraps IPv4-mapped IPv6", () => {
    const mapped = parseIp("::ffff:127.0.0.1")!;
    expect(mapped.version).toBe(6);
    expect(unwrapIpv4Mapped(mapped).canonical).toBe("127.0.0.1");
    expect(ipEquals(mapped, parseIp("127.0.0.1")!)).toBe(true);
  });

  it("classifies restricted ranges", () => {
    expect(classifyIp(parseIp("10.0.0.1")!).isPrivate).toBe(true);
    expect(classifyIp(parseIp("172.16.5.4")!).isPrivate).toBe(true);
    expect(classifyIp(parseIp("192.168.1.1")!).isPrivate).toBe(true);
    expect(classifyIp(parseIp("127.0.0.1")!).isLoopback).toBe(true);
    expect(classifyIp(parseIp("169.254.1.1")!).isLinkLocal).toBe(true);
    expect(classifyIp(parseIp("169.254.169.254")!).isMetadata).toBe(true);
    expect(classifyIp(parseIp("100.64.0.1")!).isCGNAT).toBe(true);
    expect(classifyIp(parseIp("224.0.0.1")!).isMulticast).toBe(true);
    expect(classifyIp(parseIp("8.8.8.8")!).isSpecial).toBe(false);
    expect(classifyIp(parseIp("2606:4700:4700::1111")!).isSpecial).toBe(false);
  });
});

describe("CIDR", () => {
  it("matches addresses in range", () => {
    const cidr = parseCidr("198.51.100.0/24")!;
    expect(cidrContains(cidr, parseIp("198.51.100.77")!)).toBe(true);
    expect(cidrContains(cidr, parseIp("198.51.101.1")!)).toBe(false);
  });
  it("matches IPv6 CIDR", () => {
    const cidr = parseCidr("2001:db8::/32")!;
    expect(cidrContains(cidr, parseIp("2001:db8:1::5")!)).toBe(true);
    expect(cidrContains(cidr, parseIp("2001:db9::5")!)).toBe(false);
  });
  it("finds an IP in a CIDR list", () => {
    expect(ipInCidrList(parseIp("10.1.2.3")!, ["192.168.0.0/16", "10.0.0.0/8"])).not.toBeNull();
  });
});

describe("domain handling", () => {
  it("canonicalizes hosts", () => {
    expect(canonicalHost("WWW.Example.COM.")).toBe("www.example.com");
    expect(canonicalHost("[::1]")).toBe("::1");
  });
  it("validates hostnames", () => {
    expect(isValidHostname("example.com")).toBe(true);
    expect(isValidHostname("sub.example.co.uk")).toBe(true);
    expect(isValidHostname("bad_host.example.com")).toBe(true);
    expect(isValidHostname("exa mple.com")).toBe(false);
    expect(isValidHostname("-lead.example.com")).toBe(false);
    expect(isValidHostname("1.2.3.4")).toBe(false);
  });
  it("computes registrable domain via PSL", () => {
    expect(registrableDomain("www.example.co.uk")).toBe("example.co.uk");
    expect(registrableDomain("a.b.example.com")).toBe("example.com");
    expect(registrableDomain("example.com")).toBe("example.com");
    expect(registrableDomain("127.0.0.1")).toBeNull();
  });
  it("computes public suffix", () => {
    expect(publicSuffix("www.example.co.uk")).toBe("co.uk");
  });
});

describe("URL parsing", () => {
  it("normalizes scheme/host and strips default ports", () => {
    const u = parseUrl("HTTPS://WWW.Example.COM:443/Path?x=1#frag");
    expect(u.scheme).toBe("https");
    expect(u.host).toBe("www.example.com");
    expect(u.port).toBeNull();
    expect(u.path).toBe("/Path");
    expect(u.query).toBe("x=1");
    expect(u.fragment).toBe("frag");
    expect(u.canonical).toBe("https://www.example.com/Path?x=1");
  });
  it("keeps non-default ports", () => {
    const u = parseUrl("http://example.com:8080/a");
    expect(u.port).toBe(8080);
    expect(u.canonical).toBe("http://example.com:8080/a");
  });
  it("rejects unsupported schemes by default", () => {
    expect(tryParseUrl("ftp://example.com/x")).toBeNull();
    expect(tryParseUrl("javascript:alert(1)")).toBeNull();
    expect(tryParseUrl("not-a-url")).toBeNull();
  });
  it("records query keys", () => {
    const u = parseUrl("https://example.com/p?b=2&a=1&a=3");
    expect(u.queryKeys.sort()).toEqual(["a", "b"]);
  });
});
