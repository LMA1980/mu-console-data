______________________________________________________________________

## name: mu-console-data description: "Implement, test, and consume the mu-console-data crate for dedicated Web Worker state management, event coalescing, and offline data storage in MuConsole."

# `mu-console-data` Architecture & Guidelines

Use these guidelines when developing or integrating `mu-console-data`, the dedicated Web Worker data processing engine for MuConsole:

## 1. Engine & Event Loop

- **Clock-Driven State Machine (`engine`)**:
  - The worker runs an event-driven loop via `Engine::step` and `Engine::handle_command`.
  - Side effects (`Effect`) are returned by pure engine methods and dispatched by the WASM glue (`wasm.rs`).
  - Supports dynamic scenario playback (`?scenario=<name>`), live SSE streams, and fallback offline polling.

## 2. In-Memory Store & Coalescing

- **Normalized Entity Store (`store`)**:
  - Maintains state for repositories, pipeline runs, stages, canary deployments, and host metrics.
  - Generates compact `ViewModel` diffs against previous state representations.
- **Throttling & Coalescing (`coalesce`)**:
  - Throttles UI message dispatch to `<= 10 Hz` (`MAX_PATCH_HZ = 10`) during high-frequency telemetry streams.
  - Detects tab visibility state; switches to low-frequency heartbeat emission when the browser tab is hidden to conserve power and CPU.

## 3. Resilience & Offline Support

- **SSE Stream Parsing (`sse`)**:
  - WHATWG event stream specification compliant parser with support for multi-line data frames, BOM stripping, and custom retry intervals.
  - Automatic exponential backoff with deterministic jitter on connection dropouts.
- **CacheStorage Persistence (`offline`)**:
  - Persists serialized snapshots into the browser `CacheStorage` API under schema-watermarked keys.
  - Automatically recovers and replays cached snapshots during network interruptions.

## 4. Privacy & Lab Boundary Invariants

- **Public Repository Cleanliness**:
  - Public documentation, logs, and skills must never expose internal hostnames or private network ranges.
  - Use generic placeholders (`node-a`, `worker-riscv64`, `192.0.2.x`) across all tests and documentation.
