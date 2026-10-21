import { describe, expect, it } from "vitest";
import { formatCents, parseEuros } from "./money.js";

describe("parseEuros", () => {
  it.each([
    ["25", 2500],
    ["12,5", 1250],
    ["19,99", 1999],
    ["0.01", 1],
    [" 1 000 ", 100000],
    ["10000", 1_000_000],
  ])("%s → %i centimes", (input, cents) => {
    expect(parseEuros(input)).toBe(cents);
  });

  it.each(["", "abc", "-5", "0", "0,00", "1,999", "10000,01", "1e3", "12,"])("refuse %s", (input) => {
    expect(parseEuros(input)).toBeNull();
  });
});

describe("formatCents", () => {
  it("affiche des euros à la française", () => {
    // Intl insère des espaces insécables : on les normalise pour comparer.
    expect(formatCents(150000).replace(/\s/g, " ")).toBe("1 500,00 €");
  });
});
