import { describe, expect, it } from "vitest";
import { parseSse } from "./sse.js";
import { overall } from "./status.js";

describe("parseSse", () => {
  it("lit les événements complets et garde le morceau incomplet", () => {
    const text = 'event: services\ndata: {"a":1}\n\nevent: heartbeat\ndata: {"at":"x"}\n\nevent: serv';
    const { events, rest } = parseSse(text);
    expect(events).toEqual([
      { event: "services", data: { a: 1 } },
      { event: "heartbeat", data: { at: "x" } },
    ]);
    expect(rest).toBe("event: serv");
  });

  it("reconstitue un événement coupé en deux par le réseau", () => {
    const first = parseSse('event: services\ndata: {"a"');
    expect(first.events).toEqual([]);
    const second = parseSse(first.rest + ':2}\n\n');
    expect(second.events).toEqual([{ event: "services", data: { a: 2 } }]);
  });

  it("accepte les fins de ligne Windows", () => {
    expect(parseSse('event: heartbeat\r\ndata: {}\r\n\r\n').events).toEqual([{ event: "heartbeat", data: {} }]);
  });
});

const topology = (nodeStates, endToEnd = "up") => ({
  nodes: nodeStates.map((state, i) => ({ name: `n${i}`, state })),
  links: [{ source: "smoke-test", target: "bunkerweb", state: endToEnd }],
});

describe("overall", () => {
  it("opérationnelle si tout est OK", () => expect(overall(topology(["up", "up"]))).toBe("up"));
  it("dégradée si un composant flanche mais que les clients sont servis", () =>
    expect(overall(topology(["up", "degraded"]))).toBe("degraded"));
  it("en panne dès que la transaction de bout en bout échoue", () =>
    expect(overall(topology(["up", "up"], "down"))).toBe("down"));
  it("inconnue avant la première mesure", () => expect(overall(null)).toBe("unknown"));
});
