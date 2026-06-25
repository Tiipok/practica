# Диаграмма компонентов

```mermaid
graph TD
    CLI[CLI Parser\ncli_parser] -->|ExperimentConfig| Runner[ExperimentRunner]
    Runner -->|create/open| AM[ArchiveManager\nlibzip]
    Runner -->|run CPU experiment| BFE[BruteForceEngine]
    Runner -->|run GPU experiment| GPUEngine[BruteForceEngine\nGPU mode]
    Runner -->|collect metrics| SC[StatsCollector]
    Runner -->|save results| RS[ResultsStorage\nSQLite3]

    BFE -->|uses| PG[PasswordGenerator\nCharset]
    BFE -->|checks passwords| PC[PasswordChecker\nlibzip]
    BFE -->|manages| WP[WorkerPool\nstd::thread × N]

    GPUEngine -->|uses| PG
    GPUEngine -->|batch check| GC[GpuChecker]
    GC -->|dispatches| MK[MetalKernel\ninline shaders]
    GC -->|expected bytes| ZU[ZipCryptoUtil]
    MK -->|ZipCrypto kernel| METAL1[Metal GPU]
    MK -->|AES-256 kernel| METAL2[Metal GPU]

    SC -->|time| CHRONO[std::chrono]
    SC -->|memory/cpu| MACH[Mach API]

    RS -->|export| CSV[CSV Export\nwith quoting]
    CSV -->|visualization| PY[generate_report.py\nmatplotlib]
    PY -->|output| PDF[report.pdf]

    AM -->|create/verify| LIBZIP[libzip C API]
    PC -->|verify| LIBZIP

    subgraph "Apple Silicon M4"
        WP
        MACH
        CHRONO
        METAL1
        METAL2
    end
```
