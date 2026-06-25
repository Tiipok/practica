# Диаграмма последовательности запуска эксперимента

## Режим CPU (test suite)

```mermaid
sequenceDiagram
    actor User
    participant CLI as CliParser
    participant Runner as ExperimentRunner
    participant AM as ArchiveManager
    participant Gen as PasswordGenerator
    participant Engine as BruteForceEngine
    participant Checker as PasswordChecker
    participant Stats as StatsCollector
    participant DB as ResultsStorage

    User->>CLI: zipbrute --charset digits --min-len 4 --max-len 4 --threads 4
    CLI->>CLI: parse args → ExperimentConfig
    CLI->>Runner: ExperimentRunner(config)

    Runner->>DB: initialize() CREATE TABLE

    alt not skip_test_suite
        Runner->>AM: create_test_suite(output_dir, source_file)
        AM->>AM: create 8 test ZIP archives (libzip)
        AM-->>Runner: vector<ArchiveInfo>
    end

    loop for each archive
        Runner->>Gen: PasswordGenerator(charset, length, length)
        Gen-->>Runner: total_space = N

        Runner->>Stats: start()
        Runner->>Engine: run(generator, num_threads)

        par thread 1
            Engine->>Gen: copy generator, set_range(0, N/4)
            loop while not found and range not exhausted
                Gen->>Gen: next() → password
                Engine->>Checker: check(archive, password)
                Checker->>Checker: zip_fopen_encrypted + zip_fread
                Checker-->>Engine: true/false
                alt password found
                    Engine->>Engine: atomic found = true
                end
            end
        and thread 2
            Engine->>Gen: copy generator, set_range(N/4, N/2)
        and thread 3
            Engine->>Gen: copy generator, set_range(N/2, 3N/4)
        and thread 4
            Engine->>Gen: copy generator, set_range(3N/4, N)
        end

        Engine->>Engine: join all threads
        Engine-->>Runner: BruteForceResult

        Runner->>Stats: stop()
        Stats-->>Runner: PerformanceMetrics

        Runner->>DB: save_result(record)
        DB-->>Runner: id
    end

    Runner->>DB: export_csv(results.csv)
    Runner-->>User: "Results saved"
```

## Режим GPU

```mermaid
sequenceDiagram
    actor User
    participant Runner as ExperimentRunner
    participant Gen as PasswordGenerator
    participant Engine as BruteForceEngine
    participant GC as GpuChecker
    participant MK as MetalKernel
    participant GPU as Metal GPU
    participant Checker as PasswordChecker
    participant DB as ResultsStorage

    User->>Runner: zipbrute --gpu --archive test.zip
    Runner->>Engine: run_gpu(generator, batch_size=65536, known_password)
    Engine->>GC: GpuChecker(archive_path, known_password)

    GC->>MK: initialize("crack_zipcrypto")
    MK->>GPU: newLibraryWithSource + compile
    GPU-->>MK: MTLComputePipelineState
    GC->>GC: extract_zipcrypto_data() from archive
    GC->>GC: compute expected bytes via ZipCryptoUtil

    loop batch processing
        Engine->>Gen: next() × 65536
        Engine->>GC: check_batch(passwords)
        GC->>MK: Metal buffers (passwords, lengths, enc_header, expected)
        MK->>GPU: dispatchThreads
        GPU-->>MK: atomic found_flag + found_idx
        MK-->>GC: candidate found (or false)

        alt GPU candidate found
            GC-->>Engine: candidate password
            Engine->>Checker: verify via libzip
            alt libzip confirms
                Engine-->>Runner: BruteForceResult (found = true)
            else false positive
                Engine->>Gen: reset_to(index + 1), continue
            end
        end
    end

    Runner->>DB: save_result(record, execution_mode="GPU")
```

## Режим benchmark

```mermaid
sequenceDiagram
    actor User
    participant Runner as ExperimentRunner
    participant AM as ArchiveManager
    participant Engine as BruteForceEngine
    participant DB as ResultsStorage

    User->>Runner: zipbrute --benchmark --mode both --repeat 3
    Runner->>AM: create_benchmark_suite(bench_data_dir)
    AM-->>Runner: 20 archive files (4 charsets × 5 lengths)

    loop repeat = 3 times
        loop for each archive
            alt CPU mode
                loop thread_counts [1,2,4,6,8,10]
                    Runner->>Engine: run(generator, threads)
                end
            end
            alt GPU mode
                Runner->>Engine: run_gpu(generator, 65536, password)
            end
            Runner->>DB: save_result(record)
        end
    end

    Runner->>DB: export_csv(results.csv)
```

## Этапы обработки

1. **Парсинг аргументов** — CLI разбирает параметры, валидирует (включая GPU и benchmark флаги)
2. **Инициализация БД** — создание таблицы experiments в SQLite (все поля включая execution_mode)
3. **Создание тестовых архивов** — ArchiveManager фабрика (libzip, без shell-команд)
4. **Запуск эксперимента** — для каждого архива:
   - Инициализация генератора паролей (Charset хранится по значению)
   - Замер времени (StatsCollector)
   - CPU: многопоточный перебор с atomic-флагом остановки
   - GPU: батчевый перебор через Metal kernel с верификацией через libzip
   - Фиксация результата и метрик
5. **Сохранение** — запись в SQLite + экспорт CSV (с экранированием полей)
