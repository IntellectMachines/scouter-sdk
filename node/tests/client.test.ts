import { describe, it, expect } from "vitest";
import { ScouterClient } from "../src/client.js";
import { BackendClient } from "../src/api/backend.js";
import { Decision } from "../src/models.js";

describe("ScouterClient", () => {
  it("initializes with default options", () => {
    const client = new ScouterClient();
    expect(client.mode).toBe("audit");
    expect(client.traceId).toMatch(/^trace-/);
    expect(client.backend).toBeNull();
  });

  it("initializes with backend URL", () => {
    const client = new ScouterClient({
      apiKey: "test-key",
      backendUrl: "http://localhost:8000",
    });
    expect(client.backend).not.toBeNull();
    expect(client.backendUrl).toBe("http://localhost:8000");
  });

  it("generates new trace IDs", () => {
    const client = new ScouterClient();
    const t1 = client.traceId;
    const t2 = client.newTrace();
    expect(t1).not.toBe(t2);
    expect(t2).toMatch(/^trace-/);
  });

  it("registers and retrieves intents", () => {
    const client = new ScouterClient();
    const intent = client.registry.register({
      agentId: "test-agent",
      intent: "Process customer support tickets",
      permittedActions: ["lookup_order", "process_refund"],
      excludedActions: ["delete_customer"],
    });
    expect(intent.agentId).toBe("test-agent");
    expect(intent.permittedActions).toContain("lookup_order");

    const found = client.registry.get(intent.intentId);
    expect(found).toBeDefined();
    expect(found!.naturalLanguage).toBe("Process customer support tickets");
  });

  it("evaluates actions locally", () => {
    const client = new ScouterClient();
    const intent = client.registry.register({
      agentId: "test-agent",
      intent: "Process customer support tickets",
      permittedActions: ["lookup_order", "process_refund"],
      excludedActions: ["delete_customer"],
    });

    const result = client.engine.evaluate(
      {
        actionType: "lookup_order",
        targetSystem: "orders",
        payloadSummary: "Looking up order #1234",
        delegationDepth: 0,
      },
      intent,
    );

    expect(result.evaluation.calculatedDecision).toBe(Decision.PASS_THROUGH);
  });

  it("evaluates excluded actions as risky", () => {
    const client = new ScouterClient();
    const intent = client.registry.register({
      agentId: "test-agent",
      intent: "Process customer support tickets",
      permittedActions: ["lookup_order"],
      excludedActions: ["delete_customer"],
    });

    const result = client.engine.evaluate(
      {
        actionType: "delete_customer",
        targetSystem: "crm",
        payloadSummary: "Deleting customer record",
        delegationDepth: 0,
      },
      intent,
    );

    // delete has high irreversibility (0.95) → ESCALATE
    expect(result.evaluation.calculatedDecision).toBe(Decision.ESCALATE);
  });
});

describe("BackendClient DID methods", () => {
  it("has registerAgentDID method", () => {
    const client = new BackendClient("http://localhost:8000", { apiKey: "test" });
    expect(typeof client.registerAgentDID).toBe("function");
  });

  it("has resolveDID method", () => {
    const client = new BackendClient("http://localhost:8000", { apiKey: "test" });
    expect(typeof client.resolveDID).toBe("function");
  });

  it("has revokeDID method", () => {
    const client = new BackendClient("http://localhost:8000", { apiKey: "test" });
    expect(typeof client.revokeDID).toBe("function");
  });

  it("has rotateDIDKey method", () => {
    const client = new BackendClient("http://localhost:8000", { apiKey: "test" });
    expect(typeof client.rotateDIDKey).toBe("function");
  });

  it("registerAgentDID returns null on connection error", async () => {
    const client = new BackendClient("http://localhost:1", { timeout: 100 });
    const result = await client.registerAgentDID({ agentId: "test" });
    expect(result).toBeNull();
  });

  it("resolveDID returns null on connection error", async () => {
    const client = new BackendClient("http://localhost:1", { timeout: 100 });
    const result = await client.resolveDID("did:scouter:test");
    expect(result).toBeNull();
  });
});
