const MASK_64 = (1n << 64n) - 1n;
const FIRST_HASH_ID = 4;
const PERSONALIZATION = new TextEncoder().encode("mumal-v1");

const IV = Object.freeze([
  0x6a09e667f3bcc908n,
  0xbb67ae8584caa73bn,
  0x3c6ef372fe94f82bn,
  0xa54ff53a5f1d36f1n,
  0x510e527fade682d1n,
  0x9b05688c2b3e6c1fn,
  0x1f83d9abfb41bd6bn,
  0x5be0cd19137e2179n,
]);

const SIGMA = Object.freeze([
  [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
  [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
  [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
  [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
  [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
  [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
  [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
  [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
  [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
  [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
  [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
  [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
]);

let activeModel = null;
const tokenCache = new Map();

function read64(bytes, offset) {
  let value = 0n;
  for (let index = 0; index < 8; index += 1) {
    value |= BigInt(bytes[offset + index] || 0) << BigInt(index * 8);
  }
  return value;
}

function rotateRight(value, amount) {
  const shift = BigInt(amount);
  return ((value >> shift) | (value << (64n - shift))) & MASK_64;
}

function mix(values, a, b, c, d, left, right) {
  values[a] = (values[a] + values[b] + left) & MASK_64;
  values[d] = rotateRight(values[d] ^ values[a], 32);
  values[c] = (values[c] + values[d]) & MASK_64;
  values[b] = rotateRight(values[b] ^ values[c], 24);
  values[a] = (values[a] + values[b] + right) & MASK_64;
  values[d] = rotateRight(values[d] ^ values[a], 16);
  values[c] = (values[c] + values[d]) & MASK_64;
  values[b] = rotateRight(values[b] ^ values[c], 63);
}

function compressBlake2b(state, block, count, isLast) {
  const message = Array.from({ length: 16 }, (_, index) =>
    read64(block, index * 8),
  );
  const values = [...state, ...IV];
  values[12] ^= count & MASK_64;
  values[13] ^= count >> 64n;
  if (isLast) values[14] ^= MASK_64;

  for (const order of SIGMA) {
    mix(values, 0, 4, 8, 12, message[order[0]], message[order[1]]);
    mix(values, 1, 5, 9, 13, message[order[2]], message[order[3]]);
    mix(values, 2, 6, 10, 14, message[order[4]], message[order[5]]);
    mix(values, 3, 7, 11, 15, message[order[6]], message[order[7]]);
    mix(values, 0, 5, 10, 15, message[order[8]], message[order[9]]);
    mix(values, 1, 6, 11, 12, message[order[10]], message[order[11]]);
    mix(values, 2, 7, 8, 13, message[order[12]], message[order[13]]);
    mix(values, 3, 4, 9, 14, message[order[14]], message[order[15]]);
  }
  for (let index = 0; index < 8; index += 1) {
    state[index] = (state[index] ^ values[index] ^ values[index + 8]) & MASK_64;
  }
}

function blake2b64(text) {
  const input = new TextEncoder().encode(text);
  const state = [...IV];
  state[0] ^= 0x01010008n;
  state[6] ^= read64(PERSONALIZATION, 0);

  let offset = 0;
  let count = 0n;
  while (offset + 128 < input.length) {
    const block = input.slice(offset, offset + 128);
    count += 128n;
    compressBlake2b(state, block, count, false);
    offset += 128;
  }
  const finalBlock = new Uint8Array(128);
  const remaining = input.slice(offset);
  finalBlock.set(remaining);
  count += BigInt(remaining.length);
  compressBlake2b(state, finalBlock, count, true);
  return state[0];
}

function hashedTokenId(token, vocabularySize) {
  const cacheKey = vocabularySize + ":" + token;
  if (tokenCache.has(cacheKey)) return tokenCache.get(cacheKey);
  const bucket = Number(blake2b64(token) % BigInt(vocabularySize - FIRST_HASH_ID));
  const identifier = FIRST_HASH_ID + bucket;
  tokenCache.set(cacheKey, identifier);
  return identifier;
}

function product(values) {
  return values.reduce((total, value) => total * value, 1);
}

function requiredTensorNames(layerCount) {
  const names = ["token_embedding.weight", "position_embedding.weight"];
  for (let index = 0; index < layerCount; index += 1) {
    const prefix = "encoder.layers." + index;
    names.push(
      prefix + ".self_attn.in_proj_weight",
      prefix + ".self_attn.in_proj_bias",
      prefix + ".self_attn.out_proj.weight",
      prefix + ".self_attn.out_proj.bias",
      prefix + ".linear1.weight",
      prefix + ".linear1.bias",
      prefix + ".linear2.weight",
      prefix + ".linear2.bias",
      prefix + ".norm1.weight",
      prefix + ".norm1.bias",
      prefix + ".norm2.weight",
      prefix + ".norm2.bias",
    );
  }
  names.push(
    "norm.weight",
    "norm.bias",
    "classifier.weight",
    "classifier.bias",
  );
  return names;
}

function validateManifest(manifest, buffer) {
  if (!manifest || manifest.schema !== "itcs.browser-full-model.v1") {
    throw new Error("Unsupported browser model manifest.");
  }
  if (!(buffer instanceof ArrayBuffer)) {
    throw new TypeError("Model weights must be an ArrayBuffer.");
  }
  if (buffer.byteLength !== manifest.binary.bytes || buffer.byteLength % 4) {
    throw new Error("Model binary size does not match its manifest.");
  }
  const config = manifest.config;
  const integers = [
    config.vocab_size,
    config.max_length,
    config.d_model,
    config.n_heads,
    config.n_layers,
    config.ffn_dim,
  ];
  if (integers.some((value) => !Number.isInteger(value) || value < 1)) {
    throw new Error("Model configuration is invalid.");
  }
  if (config.d_model % config.n_heads) {
    throw new Error("Model width must be divisible by its attention heads.");
  }
  for (const name of requiredTensorNames(config.n_layers)) {
    const descriptor = manifest.tensors[name];
    if (!descriptor) throw new Error("Model tensor is missing: " + name);
    if (
      !Number.isInteger(descriptor.offset) ||
      descriptor.offset < 0 ||
      descriptor.offset % 4 ||
      !Number.isInteger(descriptor.length) ||
      descriptor.length < 1 ||
      product(descriptor.shape) !== descriptor.length ||
      descriptor.offset + descriptor.length * 4 > buffer.byteLength
    ) {
      throw new Error("Model tensor layout is invalid: " + name);
    }
  }
}

export function installFullModel(manifest, buffer) {
  validateManifest(manifest, buffer);
  const tensors = new Map();
  for (const [name, descriptor] of Object.entries(manifest.tensors)) {
    tensors.set(name, {
      data: new Float32Array(buffer, descriptor.offset, descriptor.length),
      shape: descriptor.shape,
    });
  }
  activeModel = {
    manifest,
    config: manifest.config,
    tensors,
    buffer,
  };
  tokenCache.clear();
  return getFullModelStatus();
}

export function unloadFullModel() {
  activeModel = null;
  tokenCache.clear();
}

export function getFullModelStatus() {
  if (!activeModel) {
    return {
      loaded: false,
      metadata: null,
      binaryBytes: 0,
    };
  }
  return {
    loaded: true,
    metadata: activeModel.manifest.metadata,
    binaryBytes: activeModel.buffer.byteLength,
  };
}

async function sha256Hex(buffer) {
  if (!globalThis.crypto?.subtle) {
    throw new Error("Web Crypto is required to verify the model.");
  }
  const digest = await globalThis.crypto.subtle.digest("SHA-256", buffer);
  return [...new Uint8Array(digest)]
    .map((value) => value.toString(16).padStart(2, "0"))
    .join("");
}

async function readResponse(response, expectedBytes, onProgress) {
  if (!response.body?.getReader) {
    const buffer = await response.arrayBuffer();
    onProgress?.(buffer.byteLength, expectedBytes);
    return buffer;
  }
  const reader = response.body.getReader();
  const chunks = [];
  let loaded = 0;
  while (true) {
    const result = await reader.read();
    if (result.done) break;
    chunks.push(result.value);
    loaded += result.value.byteLength;
    onProgress?.(loaded, expectedBytes);
  }
  const bytes = new Uint8Array(loaded);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return bytes.buffer;
}

export async function loadFullModel(manifest, options = {}) {
  if (activeModel) return getFullModelStatus();
  const url = new URL(manifest.binary.path, import.meta.url);
  const response = await fetch(url, {
    cache: "force-cache",
    credentials: "same-origin",
  });
  if (!response.ok) {
    throw new Error("Model download failed with HTTP " + response.status + ".");
  }
  const buffer = await readResponse(
    response,
    manifest.binary.bytes,
    options.onProgress,
  );
  const digest = await sha256Hex(buffer);
  if (digest !== manifest.binary.sha256) {
    throw new Error("Downloaded model failed its SHA-256 integrity check.");
  }
  return installFullModel(manifest, buffer);
}

function tensor(name) {
  const value = activeModel?.tensors.get(name);
  if (!value) throw new Error("Model tensor unavailable: " + name);
  return value.data;
}

function layerNorm(rows, weight, bias) {
  return rows.map((row) => {
    let mean = 0;
    for (const value of row) mean += value;
    mean /= row.length;
    let variance = 0;
    for (const value of row) variance += (value - mean) ** 2;
    variance /= row.length;
    const scale = 1 / Math.sqrt(variance + 1e-5);
    const output = new Float64Array(row.length);
    for (let index = 0; index < row.length; index += 1) {
      output[index] = (row[index] - mean) * scale * weight[index] + bias[index];
    }
    return output;
  });
}

function linear(rows, weight, bias, outputWidth, inputWidth) {
  return rows.map((row) => {
    const output = new Float64Array(outputWidth);
    for (let out = 0; out < outputWidth; out += 1) {
      let value = bias[out];
      const base = out * inputWidth;
      for (let input = 0; input < inputWidth; input += 1) {
        value += row[input] * weight[base + input];
      }
      output[out] = value;
    }
    return output;
  });
}

function addRows(left, right) {
  return left.map((row, rowIndex) => {
    const output = new Float64Array(row.length);
    for (let index = 0; index < row.length; index += 1) {
      output[index] = row[index] + right[rowIndex][index];
    }
    return output;
  });
}

function errorFunction(value) {
  const sign = value < 0 ? -1 : 1;
  const magnitude = Math.abs(value);
  const term = 1 / (1 + 0.3275911 * magnitude);
  const polynomial =
    (((((1.061405429 * term - 1.453152027) * term + 1.421413741) * term -
      0.284496736) *
      term +
      0.254829592) *
      term);
  return sign * (1 - polynomial * Math.exp(-magnitude * magnitude));
}

function gelu(value) {
  return 0.5 * value * (1 + errorFunction(value / Math.SQRT2));
}

function selfAttention(rows, prefix, width, heads) {
  const projected = linear(
    rows,
    tensor(prefix + ".self_attn.in_proj_weight"),
    tensor(prefix + ".self_attn.in_proj_bias"),
    width * 3,
    width,
  );
  const headWidth = width / heads;
  const joined = rows.map(() => new Float64Array(width));

  for (let head = 0; head < heads; head += 1) {
    const headOffset = head * headWidth;
    for (let query = 0; query < rows.length; query += 1) {
      const scores = new Float64Array(rows.length);
      let maximum = -Infinity;
      for (let key = 0; key < rows.length; key += 1) {
        let score = 0;
        for (let axis = 0; axis < headWidth; axis += 1) {
          score +=
            projected[query][headOffset + axis] *
            projected[key][width + headOffset + axis];
        }
        score /= Math.sqrt(headWidth);
        scores[key] = score;
        maximum = Math.max(maximum, score);
      }
      let denominator = 0;
      for (let key = 0; key < scores.length; key += 1) {
        scores[key] = Math.exp(scores[key] - maximum);
        denominator += scores[key];
      }
      for (let axis = 0; axis < headWidth; axis += 1) {
        let value = 0;
        for (let key = 0; key < rows.length; key += 1) {
          value +=
            (scores[key] / denominator) *
            projected[key][2 * width + headOffset + axis];
        }
        joined[query][headOffset + axis] = value;
      }
    }
  }
  return linear(
    joined,
    tensor(prefix + ".self_attn.out_proj.weight"),
    tensor(prefix + ".self_attn.out_proj.bias"),
    width,
    width,
  );
}

function transformerLayer(rows, index, config) {
  const prefix = "encoder.layers." + index;
  const normalizedAttention = layerNorm(
    rows,
    tensor(prefix + ".norm1.weight"),
    tensor(prefix + ".norm1.bias"),
  );
  let hidden = addRows(
    rows,
    selfAttention(
      normalizedAttention,
      prefix,
      config.d_model,
      config.n_heads,
    ),
  );
  const normalizedFeedForward = layerNorm(
    hidden,
    tensor(prefix + ".norm2.weight"),
    tensor(prefix + ".norm2.bias"),
  );
  const expanded = linear(
    normalizedFeedForward,
    tensor(prefix + ".linear1.weight"),
    tensor(prefix + ".linear1.bias"),
    config.ffn_dim,
    config.d_model,
  );
  for (const row of expanded) {
    for (let index = 0; index < row.length; index += 1) {
      row[index] = gelu(row[index]);
    }
  }
  const projected = linear(
    expanded,
    tensor(prefix + ".linear2.weight"),
    tensor(prefix + ".linear2.bias"),
    config.d_model,
    config.ffn_dim,
  );
  hidden = addRows(hidden, projected);
  return hidden;
}

function encodeTokens(tokens, config) {
  const identifiers = [1];
  for (const token of tokens.slice(0, config.max_length - 2)) {
    identifiers.push(hashedTokenId(token, config.vocab_size));
  }
  identifiers.push(2);
  return identifiers;
}

function runModel(identifiers) {
  const config = activeModel.config;
  const tokenEmbedding = tensor("token_embedding.weight");
  const positionEmbedding = tensor("position_embedding.weight");
  let hidden = identifiers.map((identifier, position) => {
    const output = new Float64Array(config.d_model);
    const tokenOffset = identifier * config.d_model;
    const positionOffset = position * config.d_model;
    for (let axis = 0; axis < config.d_model; axis += 1) {
      output[axis] =
        tokenEmbedding[tokenOffset + axis] +
        positionEmbedding[positionOffset + axis];
    }
    return output;
  });

  for (let index = 0; index < config.n_layers; index += 1) {
    hidden = transformerLayer(hidden, index, config);
  }
  hidden = layerNorm(hidden, tensor("norm.weight"), tensor("norm.bias"));
  const pooled = new Float64Array(config.d_model);
  for (const row of hidden) {
    for (let axis = 0; axis < config.d_model; axis += 1) {
      pooled[axis] += row[axis] / hidden.length;
    }
  }
  const logits = linear(
    [pooled],
    tensor("classifier.weight"),
    tensor("classifier.bias"),
    2,
    config.d_model,
  )[0];
  const maximum = Math.max(logits[0], logits[1]);
  const clean = Math.exp(logits[0] - maximum);
  const suspicious = Math.exp(logits[1] - maximum);
  return suspicious / (clean + suspicious);
}

export function predictFullModel(tokens) {
  if (!activeModel) {
    throw new Error("Download the full µMal model before analysis.");
  }
  if (!Array.isArray(tokens) || tokens.some((token) => typeof token !== "string")) {
    throw new TypeError("Model tokens must be an array of strings.");
  }
  return runModel(encodeTokens(tokens, activeModel.config));
}

export const predictMicro = predictFullModel;
