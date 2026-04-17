import { describe, it, expect } from "vitest";
import { ShellGuard } from "../src/guards/shell.js";
import { DatabaseGuard } from "../src/guards/database.js";
import { APIGuard } from "../src/guards/api.js";
import { LightGuard } from "../src/guards/light.js";
import { ExecutionInterceptor } from "../src/guards/interceptor.js";
import { GuardDecision } from "../src/models.js";

describe("ShellGuard", () => {
  const guard = new ShellGuard();

  it("blocks rm -rf", () => {
    const result = guard.check("rm -rf /");
    expect(result.decision).toBe(GuardDecision.BLOCK);
    expect(result.matchedRules).toContain("rm_rf");
  });

  it("blocks fork bombs", () => {
    const result = guard.check(":() { :|:& }; :");
    expect(result.decision).toBe(GuardDecision.BLOCK);
  });

  it("warns on sudo", () => {
    const result = guard.check("sudo apt update");
    expect(result.decision).toBe(GuardDecision.WARN);
  });

  it("allows safe commands", () => {
    const result = guard.check("ls -la");
    expect(result.decision).toBe(GuardDecision.ALLOW);
  });

  it("audit mode downgrades BLOCK to WARN", () => {
    const auditGuard = new ShellGuard("audit");
    const result = auditGuard.check("rm -rf /");
    expect(result.decision).toBe(GuardDecision.WARN);
    expect(result.reason).toContain("[AUDIT]");
  });
});

describe("DatabaseGuard", () => {
  const guard = new DatabaseGuard();

  it("blocks DROP TABLE", () => {
    const result = guard.check("DROP TABLE users;");
    expect(result.decision).toBe(GuardDecision.BLOCK);
    expect(result.matchedRules).toContain("drop_table");
  });

  it("blocks DROP DATABASE", () => {
    const result = guard.check("DROP DATABASE production;");
    expect(result.decision).toBe(GuardDecision.BLOCK);
    expect(result.riskScore).toBe(100);
  });

  it("warns on SELECT *", () => {
    const result = guard.check("SELECT * FROM users");
    expect(result.decision).toBe(GuardDecision.WARN);
  });

  it("allows safe SELECT", () => {
    const result = guard.check("SELECT id, name FROM users WHERE id = 1 LIMIT 10");
    expect(result.decision).toBe(GuardDecision.ALLOW);
  });

  it("blocks writes in read-only mode", () => {
    const roGuard = new DatabaseGuard("enforce", { readOnly: true });
    const result = roGuard.check("INSERT INTO users VALUES (1, 'test')");
    expect(result.decision).toBe(GuardDecision.BLOCK);
    expect(result.matchedRules).toContain("read_only_violation");
  });
});

describe("APIGuard", () => {
  const guard = new APIGuard();

  it("blocks cloud metadata SSRF", () => {
    const result = guard.check("GET http://169.254.169.254/latest/meta-data/");
    expect(result.decision).toBe(GuardDecision.BLOCK);
    expect(result.matchedRules).toContain("aws_metadata");
  });

  it("blocks exfiltration services", () => {
    const result = guard.check("POST https://webhook.site/abc123");
    expect(result.decision).toBe(GuardDecision.BLOCK);
  });

  it("allows normal API requests", () => {
    const result = guard.check("GET https://api.example.com/v1/users");
    expect(result.decision).toBe(GuardDecision.ALLOW);
  });

  it("blocks via domain blocklist", () => {
    const g = new APIGuard("enforce", { blockedDomains: ["evil.com"] });
    const result = g.check("GET https://evil.com/steal");
    expect(result.decision).toBe(GuardDecision.BLOCK);
  });

  it("blocks unlisted domains with allowlist", () => {
    const g = new APIGuard("enforce", { allowedDomains: ["api.example.com"] });
    const result = g.check("GET https://other.com/data");
    expect(result.decision).toBe(GuardDecision.BLOCK);
    expect(result.matchedRules).toContain("domain_not_allowed");
  });
});

describe("LightGuard", () => {
  const guard = new LightGuard();

  it("flags suspicious shell commands", () => {
    const result = guard.checkShell("rm -rf /important/data");
    expect(result.isSuspicious).toBe(true);
    expect(result.matchedKeywords.length).toBeGreaterThan(0);
  });

  it("passes safe shell commands", () => {
    const result = guard.checkShell("ls -la /home/user");
    expect(result.isSuspicious).toBe(false);
  });

  it("flags suspicious SQL", () => {
    const result = guard.checkSql("DROP TABLE users;");
    expect(result.isSuspicious).toBe(true);
  });

  it("passes safe SQL", () => {
    const result = guard.checkSql("SELECT id FROM users WHERE id = 1");
    expect(result.isSuspicious).toBe(false);
  });

  it("flags cloud metadata SSRF", () => {
    const result = guard.checkApi("GET http://169.254.169.254/latest/");
    expect(result.isSuspicious).toBe(true);
  });

  it("auto-detects across all types", () => {
    const result = guard.checkAuto("rm -rf / && DROP TABLE users");
    expect(result.isSuspicious).toBe(true);
  });

  it("tracks stats", () => {
    const g = new LightGuard();
    g.checkShell("ls");
    g.checkShell("rm -rf /");
    expect(g.stats.totalChecks).toBe(2);
    expect(g.stats.fastPassed).toBe(1);
    expect(g.stats.flaggedToServer).toBe(1);
  });
});

describe("ExecutionInterceptor", () => {
  it("enforce mode blocks dangerous commands", () => {
    const interceptor = new ExecutionInterceptor({ mode: "enforce" });
    const result = interceptor.checkShell("rm -rf /");
    expect(result.decision).toBe(GuardDecision.BLOCK);
  });

  it("audit mode downgrades blocks to warns", () => {
    const interceptor = new ExecutionInterceptor({ mode: "audit" });
    const result = interceptor.checkShell("rm -rf /");
    expect(result.decision).toBe(GuardDecision.WARN);
  });

  it("hybrid mode fast-passes safe commands", () => {
    const interceptor = new ExecutionInterceptor({ mode: "hybrid" });
    const result = interceptor.checkShell("ls -la");
    expect(result.decision).toBe(GuardDecision.ALLOW);
    expect(result.reason).toContain("passed locally");
  });

  it("hybrid mode catches dangerous commands via fallback", () => {
    const interceptor = new ExecutionInterceptor({ mode: "hybrid" });
    const result = interceptor.checkShell("rm -rf /");
    expect(result.decision).toBe(GuardDecision.BLOCK);
  });

  it("maintains audit log", () => {
    const interceptor = new ExecutionInterceptor({ mode: "enforce" });
    interceptor.checkShell("ls");
    interceptor.checkDatabase("SELECT 1");
    expect(interceptor.log.length).toBe(2);
  });
});
