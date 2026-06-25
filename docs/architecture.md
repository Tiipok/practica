# Архитектура приложения

## Назначение

Учебно-исследовательский комплекс для исследования стойкости парольной защиты ZIP-архивов методом прямого перебора на процессорах Apple Silicon M4.

## Ограничения

- Алфавит: только строчные латинские буквы и цифры (digits, lowercase, alphanum)
- Максимальная длина пароля: 5 символов
- Типы защиты: ZipCrypto (традиционное шифрование) и AES-256
- Только тестовые архивы, созданные самостоятельно

## Компонентная модель

```
┌─────────────┐     ┌──────────────────┐     ┌─────────────────┐
│  CLI Parser │────▶│ ExperimentRunner │────▶│  ArchiveManager │
│  (cli_parser)│     │(experiment_runner)│    │ (archive_manager)│
└─────────────┘     └───────┬──────────┘     └────────┬────────┘
                            │                          │
              ┌─────────────┼─────────────┐            │ libzip
              ▼             ▼             ▼            │
     ┌────────────┐ ┌─────────────┐ ┌───────────┐     │
     │PasswordGen │ │BruteForceEng│ │StatsColl. │     │
     │(generator) │ │  (engine)   │ │  (stats)  │     │
     └─────┬──────┘ └──────┬──────┘ └─────┬─────┘     │
           │               │              │            │
           │         ┌─────▼──────┐       │            │
           │         │PasswordChk │       │            │
           │         │ (checker)  │       │            │
           │         └────────────┘       │            │
           │                              │            │
           │    ┌─────────────────┐       │            │
           │    │  GpuChecker     │       │            │
           │    │  MetalKernel    │       │            │
           │    │  (gpu/)         │       │            │
           │    └────────┬────────┘       │            │
           │             │                │            │
           │             │ Metal API      │            │
           │             │                │            │
           └─────────────┴────────────────┘            │
                                                       │
              ┌──────────────────────┐                 │
              │   ResultsStorage     │                 │
              │   (SQLite + CSV)     │                 │
              └──────────┬───────────┘                 │
                         │                             │
                         ▼                             │
              ┌──────────────────────┐                 │
              │   generate_report.py │                 │
              │   (matplotlib → PDF) │                 │
              └──────────────────────┘                 │
```

## Диаграмма компонентов

```
[CLI Parser] ──► [ExperimentRunner]
                      │
        ┌─────────────┼─────────────────┬──────────────────┐
        ▼             ▼                  ▼                   ▼
[ArchiveManager] [BruteForceEngine] [StatsCollector]   [GpuChecker]
    │                  │                   │               │
    │ libzip           ├─► [WorkerPool]    │ mach API      │ Metal API
    │                  │    (std::thread)  │ std::chrono   │ MetalKernel
    │                  │                   │               │ inline shaders
    │                  └─► [PasswordChkr]  │               │
    │                       (libzip)       │               │
    │                                      │               │
    └──────────────────────────────────────┴───────────────┘
                       │
                       ▼
               [ResultsStorage]
                 (SQLite3)
                       │
                       ▼
               [Report Exporter]
                 (CSV → Python)
                       │
                       ▼
                  [PDF Report]
```

## Описание модулей

### 1. CLI Parser (`src/app/cli_parser.h/cpp`)
Разбор аргументов командной строки, валидация параметров.

### 2. ExperimentRunner (`src/app/experiment_runner.h/cpp`)
Оркестратор экспериментов. Координирует создание тестовых архивов,
запуск перебора, сбор метрик и сохранение результатов.

### 3. ArchiveManager (`src/archive/archive_manager.h/cpp`)
- Создание тестовых ZIP-архивов с ZipCrypto/AES-256 шифрованием (libzip)
- Верификация пароля методом открытия зашифрованного файла
- Фабрика тестового набора из 8 архивов

### 4. PasswordGenerator (`src/generator/charset.h/cpp`, `password_generator.h/cpp`)
- Charset: алфавиты digits (10), lowercase (26), alphanum (36)
- PasswordGenerator: итератор по парольному пространству
  - Линейная индексация: index → password, password → index
  - Разделение пространства на диапазоны для потоков

### 5. PasswordChecker (`src/checker/password_checker.h/cpp`)
- Проверка кандидатного пароля через libzip
- Чтение зашифрованного файла с верификацией CRC

### 6. BruteForceEngine (`src/engine/brute_force_engine.h/cpp`)
- Многопоточный пул (std::thread) для CPU-перебора
- Равномерное распределение диапазонов между потоками
- atomic<bool> для сигнала остановки
- Сбор статистики по каждому потоку
- GPU-режим: батчевый перебор через GpuChecker с верификацией на CPU

### 7. GpuChecker (`src/gpu/gpu_checker.h/cpp`, `metal_kernel.h/mm`)
- Извлечение зашифрованных данных из ZIP-архива (ZipCrypto header / AES salt+verification)
- Упаковка паролей в uint64 для передачи на GPU
- MetalKernel: компиляция inline Metal shaders (ZipCrypto + AES-256)
- Батчевая проверка на GPU с атомарным флагом нахождения

### 8. ZipCryptoUtil (`src/gpu/zipcrypto_util.h/cpp`)
- CPU-side реализация ZipCrypto key schedule (CRC32, decrypt_byte)
- Предвычисление ожидаемых байт для GPU-верификации (когда известен пароль)

### 9. StatsCollector (`src/stats/stats_collector.h/cpp`)
- Замер времени (std::chrono::high_resolution_clock)
- Потребление памяти (Mach task_info)
- Загрузка CPU (Mach thread_info)

### 10. ResultsStorage (`src/storage/results_storage.h/cpp`)
- SQLite-база для хранения результатов
- Экспорт в CSV
- CRUD-операции

### 11. generate_report.py (`scripts/`)
- Чтение CSV
- Построение графиков (matplotlib)
- Генерация PDF-отчёта

## Входные данные

- Параметры командной строки: charset, длина, количество потоков, путь к архиву
- Тестовые ZIP-архивы (создаются автоматически или указываются явно)

## Выходные данные

- SQLite база данных (experiments.db)
- CSV файл (results.csv) с экранированием полей
- PDF отчёт с графиками и таблицами (report.pdf)

## Алгоритм эксперимента

1. Создание/загрузка тестового ZIP-архива с известным паролем
2. Задание параметров парольного пространства (алфавит, длина)
3. Вычисление размера пространства
4. Режим CPU: разделение пространства на N равных диапазонов (по числу потоков)
   Режим GPU: батчевое формирование паролей, отправка на Metal
5. Запуск перебора (CPU многопоточно или GPU батчами)
6. При нахождении пароля: atomic-флаг → остановка всех потоков (CPU) / верификация libzip (GPU)
7. Фиксация времени, метрик, количества проверок
8. Сохранение в БД и CSV
9. Повтор для разных параметров (длина, алфавит, потоки, тип защиты, режим CPU/GPU)
