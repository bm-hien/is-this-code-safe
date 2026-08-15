const ORIGINS = Object.freeze({
  ENV_READ: "environment",
  SENSITIVE_FILE_READ: "sensitive-local-file",
  FILE_READ: "local-file",
  SYSTEM_DISCOVERY: "host-state",
  NETWORK_RECEIVE: "network",
});

const DESTINATIONS = Object.freeze({
  FILE_WRITE: "local-artifact",
  NETWORK_SEND: "network",
  PROCESS_EXEC: "process",
  PERSISTENCE_WRITE: "persistence",
  FILE_DELETE: "filesystem-delete",
});

const TRANSFORMATIONS = Object.freeze({
  ENCODE: "encoding",
  DECODE: "decoding",
  DYNAMIC_IMPORT: "dynamic-loading",
  CODE_COMPILE: "code-compilation",
  DYNAMIC_EXEC: "dynamic-execution",
  UNSAFE_DESERIALIZE: "unsafe-deserialization",
});

const FLOW_BY_MOTIF = Object.freeze({
  credential_or_file_exfil: "sensitive-data-to-network",
  fingerprinting_transfer: "host-state-to-network",
  file_to_network: "local-file-to-network",
  download_execute: "network-to-execution",
  encoded_execution: "encoded-data-to-execution",
  persistence_write: "code-to-persistence",
  destructive_file_action: "code-to-filesystem-delete",
});

const PURPOSE_BY_MOTIF = Object.freeze({
  credential_or_file_exfil: [
    "sensitive-data-transfer",
    "a sensitive source appears on an outbound-transfer path",
  ],
  download_execute: [
    "remote-code-executor",
    "remote input appears on a code or process execution path",
  ],
  persistence_write: [
    "persistence-modifier",
    "an autostart destination is modified",
  ],
  destructive_file_action: [
    "destructive-file-operator",
    "a filesystem deletion effect is present",
  ],
});

const LOCAL_TRANSFORM_BLOCKERS = new Set([
  "NETWORK_RECEIVE",
  "NETWORK_SEND",
  "PROCESS_EXEC",
  "PERSISTENCE_WRITE",
  "SENSITIVE_FILE_READ",
]);

const IMPORT_TIME_EFFECTS = new Set([
  "DYNAMIC_EXEC",
  "PROCESS_EXEC",
  "NETWORK_SEND",
  "PERSISTENCE_WRITE",
  "FILE_DELETE",
]);

function normalize(value) {
  return String(value).toLowerCase().replaceAll("-", "_").replaceAll(" ", "_");
}

export function effectTokens(summary) {
  const output = summary.entrypoints.map(
    (value) => `EFFECT:ENTRY:${normalize(value)}`,
  );
  output.push(
    ...summary.dataOrigins.map((value) => `EFFECT:ORIGIN:${normalize(value)}`),
  );
  output.push(
    ...summary.dataDestinations.map(
      (value) => `EFFECT:DESTINATION:${normalize(value)}`,
    ),
  );
  output.push(
    ...summary.flows.map((value) => `EFFECT:FLOW:${normalize(value)}`),
  );
  output.push(
    ...summary.transformations.map(
      (value) => `EFFECT:TRANSFORM:${normalize(value)}`,
    ),
  );
  output.push(
    ...summary.purposeCandidates.map(
      (item) =>
        `PURPOSE:${normalize(item.label)}|Q:${normalize(item.confidence || "low")}`,
    ),
  );
  return output;
}

function indentation(line) {
  const prefix = line.match(/^[ \t]*/)?.[0] || "";
  return [...prefix].reduce(
    (size, character) => size + (character === "\t" ? 4 : 1),
    0,
  );
}

function maskRange(characters, start, end) {
  for (let index = start; index < end; index += 1) {
    characters[index] = " ";
  }
}
function maskLine(line, state) {
  const characters = [...line];
  let index = 0;
  while (index < line.length) {
    if (state.triple) {
      const end = line.indexOf(state.triple, index);
      if (end === -1) {
        maskRange(characters, index, line.length);
        return characters.join("");
      }
      maskRange(characters, index, end + 3);
      index = end + 3;
      state.triple = null;
      continue;
    }
    if (line[index] === "#") {
      maskRange(characters, index, line.length);
      break;
    }
    if (line[index] !== "'" && line[index] !== '"') {
      index += 1;
      continue;
    }
    const quote = line[index];
    const triple = quote.repeat(3);
    if (line.slice(index, index + 3) === triple) {
      const end = line.indexOf(triple, index + 3);
      if (end === -1) {
        state.triple = triple;
        maskRange(characters, index, line.length);
        break;
      }
      maskRange(characters, index, end + 3);
      index = end + 3;
      continue;
    }
    let end = index + 1;
    while (end < line.length) {
      if (line[end] === "\\" && end + 1 < line.length) {
        end += 2;
        continue;
      }
      if (line[end] === quote) break;
      end += 1;
    }
    const stop = Math.min(line.length, end + 1);
    maskRange(characters, index, stop);
    index = stop;
  }
  return characters.join("");
}

function structuralLines(source) {
  const state = { triple: null };
  return source.split(/\r?\n/).map((raw, index) => {
    const code = maskLine(raw, state);
    return {
      raw,
      code,
      indent: indentation(code),
      line: index + 1,
    };
  });
}

function isMainGuard(row) {
  if (!row.code.trim().startsWith("if __name__")) return false;
  return /^if\s+__name__\s*==\s*(["'])__main__\1\s*:/.test(
    row.raw.trim(),
  );
}

function mainGuards(rows) {
  const guards = [];
  for (let index = 0; index < rows.length; index += 1) {
    const row = rows[index];
    if (!isMainGuard(row)) continue;
    let end = rows.length;
    for (let cursor = index + 1; cursor < rows.length; cursor += 1) {
      const candidate = rows[cursor];
      if (candidate.code.trim() && candidate.indent <= row.indent) {
        end = candidate.line - 1;
        break;
      }
    }
    guards.push({ start: row.line, end, indent: row.indent });
  }
  return guards;
}

function callsInside(guards, rows) {
  const calls = new Set();
  for (const guard of guards) {
    for (const row of rows) {
      if (row.line <= guard.start || row.line > guard.end) continue;
      for (const match of row.code.matchAll(/\b([A-Za-z_]\w*)\s*\(/g)) {
        calls.add(match[1]);
      }
    }
  }
  return calls;
}

function localPipelines(events) {
  const grouped = new Map();
  for (const event of events) {
    if (!grouped.has(event.function)) grouped.set(event.function, new Set());
    grouped.get(event.function).add(event.op);
  }
  return new Set(
    [...grouped.entries()]
      .filter(
        ([name, operations]) =>
          name !== "<module>" &&
          operations.has("FILE_READ") &&
          operations.has("FILE_WRITE"),
      )
      .map(([name]) => name),
  );
}

function codeAnchors(rows) {
  const anchors = new Set();
  const lines = new Set();
  for (const row of rows) {
    const code = row.code;
    if (/^\s*(?:import\s+ast\b|from\s+ast\s+import\b)/.test(code)) {
      anchors.add("ast-api");
      lines.add(row.line);
    }
    if (/\b(?:ast\.)?(?:NodeVisitor|NodeTransformer)\b/.test(code)) {
      anchors.add("ast-visitor");
      lines.add(row.line);
    }
    if (/\bast\.(?:parse|unparse)\s*\(/.test(code)) {
      anchors.add("ast-api");
      lines.add(row.line);
    }
    if (/\.(?:parse|unparse)\s*\(/.test(code) && anchors.has("ast-api")) {
      lines.add(row.line);
    }
    if (/\b(?:builtins\.)?compile\s*\(/.test(code)) {
      anchors.add("runtime-compiler");
      lines.add(row.line);
    }
  }
  return { anchors, lines };
}

function motifCandidates(events, motifs) {
  const output = [];
  const seen = new Set();
  for (const motif of motifs) {
    const policy = PURPOSE_BY_MOTIF[motif.motif];
    if (!policy || seen.has(policy[0])) continue;
    seen.add(policy[0]);
    output.push({
      label: policy[0],
      confidence: motif.confidence || "low",
      reason: policy[1],
      lines: motif.eventIndexes
        .map((index) => events[index]?.line)
        .filter(Boolean)
        .sort((left, right) => left - right),
    });
  }
  return output;
}

export function summarizeEffects(source, events, motifs) {
  const rows = structuralLines(source);
  const guards = mainGuards(rows);
  const mainCalls = callsInside(guards, rows);
  const pipelines = localPipelines(events);
  const reachablePipelines = new Set(
    [...pipelines].filter((name) => mainCalls.has(name)),
  );
  const { anchors, lines: anchorLines } = codeAnchors(rows);
  const operations = new Set(events.map((event) => event.op));

  const entrypoints = [];
  if (guards.length) entrypoints.push("explicit-cli");
  const importTime = events.some(
    (event) =>
      event.function === "<module>" &&
      IMPORT_TIME_EFFECTS.has(event.op) &&
      !guards.some(
        (guard) => event.line >= guard.start && event.line <= guard.end,
      ),
  );
  if (importTime) entrypoints.push("import-time-effects");
  if (!entrypoints.length) {
    entrypoints.push(
      rows.some((row) => /^\s*(?:async\s+)?def\s+/.test(row.code))
        ? "library-callable"
        : "module-import",
    );
  }

  const origins = [...new Set(
    events.map((event) => ORIGINS[event.op]).filter(Boolean),
  )].sort();
  const destinations = [...new Set(
    events.map((event) => DESTINATIONS[event.op]).filter(Boolean),
  )].sort();
  const transformations = new Set(
    events.map((event) => TRANSFORMATIONS[event.op]).filter(Boolean),
  );
  if (anchors.size >= 2) transformations.add("code-generation");

  const flows = new Set(
    motifs
      .filter((motif) => motif.evidenceKind !== "proximity")
      .map((motif) => FLOW_BY_MOTIF[motif.motif])
      .filter(Boolean),
  );
  if (reachablePipelines.size) {
    flows.add("local-file-to-local-artifact");
  }

  const candidates = motifCandidates(events, motifs);
  const blocked = [...LOCAL_TRANSFORM_BLOCKERS].some((op) =>
    operations.has(op),
  );
  if (
    reachablePipelines.size &&
    anchors.size >= 2 &&
    !blocked &&
    !candidates.length
  ) {
    const pipelineLines = events
      .filter(
        (event) =>
          reachablePipelines.has(event.function) &&
          ["FILE_READ", "FILE_WRITE"].includes(event.op),
      )
      .map((event) => event.line);
    candidates.push({
      label: "local-code-transformer",
      confidence: "medium",
      reason:
        "an explicit CLI reaches local-file input/output and code-generation structures",
      lines: [...new Set([...pipelineLines, ...anchorLines])]
        .sort((left, right) => left - right)
        .slice(0, 12),
    });
  }

  const summary = {
    entrypoints,
    dataOrigins: origins,
    dataDestinations: destinations,
    transformations: [...transformations].sort(),
    flows: [...flows].sort(),
    primaryPurpose: candidates[0]?.label || "unknown",
    purposeCandidates: candidates,
  };
  return { ...summary, tokens: effectTokens(summary) };
}
