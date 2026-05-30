import { createRequire } from "node:module";
import type * as Sodium from "libsodium-wrappers";

const require = createRequire(import.meta.url);

// The package's Node ESM entry imports a sibling wasm module that is published
// by the transitive `libsodium` package, not beside the wrapper file. Loading
// the CommonJS entry keeps Node runtime imports reliable while preserving the
// public SDK's ESM surface.
const sodium = require("libsodium-wrappers") as typeof Sodium;

export default sodium;
