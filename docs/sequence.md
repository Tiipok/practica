# Диаграмма последовательности запуска эксперимента

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
        AM->>AM: create 8 test ZIP archives
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
            ...
        and thread 3
            Engine->>Gen: copy generator, set_range(N/2, 3N/4)
            ...
        and thread 4
            Engine->>Gen: copy generator, set_range(3N/4, N)
            ...
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

## Этапы обработки

1. **Парсинг аргументов** — CLI разбирает параметры, валидирует
2. **Инициализация БД** — создание таблицы experiments в SQLite
3. **Создание тестовых архивов** — ArchiveManager фабрика (опционально)
4. **Запуск эксперимента** — для каждого архива:
   - Инициализация генератора паролей
   - Замер времени
   - Многопоточный перебор
   - Фиксация результата и метрик
5. **Сохранение** — запись в SQLite + экспорт CSV
