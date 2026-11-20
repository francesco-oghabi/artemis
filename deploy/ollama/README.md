# Ollama serving config for Artemis

Everything changed on the local LLM backend (Ollama) to run Artemis's planner and
workers, with the reason for each choice. The point is not just *what* the values are
but *why* they are tuned this way, so the setup can be rebuilt and understood.

These files are versioned copies of the live config: this repo is the source of truth,
the machine is aligned to it (see "How to apply").

## Reference hardware

- GPU: a 32 GB consumer GPU (reference: NVIDIA RTX 5090, 32 GB VRAM).
- ~24 CPU cores, ~64 GB RAM.
- Ollama as a systemd service (user `ollama`). The model store path is deployment
  specific (see `systemd/ollama.service.d/models.conf`, adjust to your host).

## Call chain

```
Artemis (worker/planner)  ->  [optional logprobs proxy]  ->  ollama serve :11434
```

- Artemis points at an OpenAI-compatible endpoint (`.../v1`) configured as an LLM
  profile in the UI.
- An optional local logprobs-capture proxy (external to this repo) can sit in front of
  Ollama for measurement; it uses a threaded HTTP server and does not serialize
  inference, so it is not a concurrency bottleneck.
- The real Ollama is on `:11434`, which is where concurrency is governed.

## The model: `qwen3-coder-ctx32k-t03-s42`

Modelfile: `Modelfile.qwen3-coder-ctx32k-t03-s42`.

Base: Qwen3-Coder-30B-A3B-Instruct, Q4_K_M (qwen3moe, 30.5B total / ~3B active, GQA
with 4 KV heads, 48 layers, head_dim 64).

| parameter | value | why |
|---|---|---|
| `seed` | 42 | reproducible, comparable benchmark runs |
| `temperature` | 0.3 | low (not zero) sampling variance for the same purpose |
| `num_ctx` | 32768 | multi-step agentic sessions accumulate a lot of context; avoids truncation mid-intent |
| `top_k` / `top_p` | 20 / 0.8 | Qwen3-Coder recommended defaults |
| `repeat_penalty` | 1.05 | recommended default |

## Parallelism: `OLLAMA_NUM_PARALLEL=2`

Drop-in `systemd/ollama.service.d/parallel.conf`.

**Problem.** Artemis can launch N concurrent workers (`settings.workers`). If Ollama
serves only one sequence at a time, the extra workers queue serially and the parallelism
is fake. `OLLAMA_NUM_PARALLEL` sets how many sequences a single loaded model actually
serves in parallel.

**Rule.** `OLLAMA_NUM_PARALLEL >= settings.workers`, otherwise workers past the limit
wait. Here: workers=2 on the Artemis side, NUM_PARALLEL=2 on the Ollama side.

**VRAM cost (why 2 fits and why not jump to 4).** Each parallel slot has its own KV
cache. Thanks to GQA (only 4 KV heads) a 32k cache is cheap:

```
KV/slot = 2(K+V) * 48 layers * 4 kv_heads * 64 head_dim * 32768 ctx * 2 bytes(f16)
        ~= 1.5 GB
```

Budget on a 32 GB GPU:

| concurrent slots | estimated VRAM | fits in 32 GB? |
|---|---|---|
| 1 | ~21 GB (weights ~19 + 1x1.5 + buffers) | yes, ample |
| 2 | ~23 GB | yes, comfortable (chosen) |
| 3 | ~25 GB | yes |
| 4 | ~27 GB | yes, tight |

VRAM is not the constraint; the real limit is the memory bandwidth shared across slots
(per-slot throughput drops while the aggregate rises). Start at 2 and consider 3 only
with run data in hand (`nvidia-smi` + tokens/sec).

## Link to the Artemis tuning

This Ollama-side tuning pairs with two Artemis-side choices (see `docs/ROADMAP.md`):

1. **Per-intent worker budget** (worker agent: `max_turns=100`, `run_seconds=720`):
   prevents a single pathological intent from sequestering a worker. On budget exhaustion
   the worker is freed (`exhausted`) and reclaims the next intent. Without it, more
   workers would only amplify the waste.
2. **Post-goal-met frontier drain**: executes the queued breadth intents before closing.
   More workers plus Ollama parallelism means a faster, deeper drain.

Agreed values:

| where | key | value | note |
|---|---|---|---|
| Artemis DB `settings` | `workers` | 2 | read at each task start, no restart |
| Artemis DB `agents` (worker) | `max_turns` | 100 | per-intent step cap |
| Artemis DB `agents` (worker) | `run_seconds` | 720 | per-intent wall-clock cap (12 min) |
| Ollama systemd | `OLLAMA_NUM_PARALLEL` | 2 | must be >= workers |

## How to apply

Systemd drop-ins (needs `sudo`; copy from the repo so the host stays aligned):

```bash
cd <artemis-repo>
sudo mkdir -p /etc/systemd/system/ollama.service.d
sudo cp deploy/ollama/systemd/ollama.service.d/*.conf /etc/systemd/system/ollama.service.d/
sudo systemctl daemon-reload
sudo systemctl restart ollama
```

Verify:

```bash
systemctl show ollama -p Environment | tr ' ' '\n' | grep PARALLEL   # OLLAMA_NUM_PARALLEL=2
```

The restart unloads the model from VRAM; it reloads on the first request. Do it with no
task running.

Custom model (if it needs rebuilding):

```bash
ollama create qwen3-coder-ctx32k-t03-s42 -f deploy/ollama/Modelfile.qwen3-coder-ctx32k-t03-s42
```

(First set the Modelfile's `FROM` to the base model, see the comment in the file.)
