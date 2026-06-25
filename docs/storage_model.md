# Модель хранения результатов

## Схема SQLite

```sql
CREATE TABLE experiments (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp   TEXT NOT NULL,
    archive_name TEXT NOT NULL,
    archive_path TEXT,
    archive_size_bytes INTEGER,
    protection_type TEXT,       -- ZipCrypto | AES-256
    charset_name TEXT,          -- digits | lowercase | alphanum
    charset_size INTEGER,       -- 10 | 26 | 36
    password_length INTEGER,    -- 1..5
    total_space_size INTEGER,   -- размер парольного пространства
    num_threads INTEGER,        -- количество потоков
    total_checks INTEGER,       -- выполнено проверок
    total_time_ms REAL,         -- общее время (мс)
    checks_per_second REAL,     -- скорость (проверок/сек)
    cpu_load_percent REAL,      -- загрузка CPU (%)
    memory_resident_bytes INTEGER,
    memory_virtual_bytes INTEGER,
    compiler_flags TEXT,        -- Debug/Release
    cpu_model TEXT,             -- Apple M4
    password_found INTEGER,     -- 0 или 1
    found_password TEXT,        -- найденный пароль (если найден)
    execution_mode TEXT         -- CPU или GPU
);
```

## Поля CSV (экспорт)

| Поле | Тип | Описание |
|------|-----|----------|
| id | int | Идентификатор записи |
| timestamp | string | Дата/время эксперимента |
| archive_name | string | Имя тестового архива |
| archive_size_bytes | int | Размер архива в байтах |
| protection_type | string | Тип шифрования |
| charset_name | string | Имя алфавита |
| charset_size | int | Размер алфавита |
| password_length | int | Длина пароля |
| total_space_size | int | Размер пространства |
| num_threads | int | Количество потоков |
| total_checks | int | Проверено паролей |
| total_time_ms | float | Время (мс) |
| checks_per_second | float | Скорость |
| cpu_load_percent | float | Загрузка CPU |
| memory_resident_bytes | int | Резидентная память |
| memory_virtual_bytes | int | Виртуальная память |
| compiler_flags | string | Флаги компиляции |
| cpu_model | string | Модель процессора |
| password_found | int | Пароль найден (0/1) |
| found_password | string | Найденный пароль |
| execution_mode | string | Режим выполнения (CPU / GPU) |

## Рекомендуемые эксперименты

Для сбора данных в матричном режиме использовать:
```bash
./build/zipbrute --output-dir results --charset digits    --matrix
./build/zipbrute --output-dir results --charset lowercase --matrix
./build/zipbrute --output-dir results --charset alphanum  --matrix
```

Сравнение количества потоков:
```bash
./build/zipbrute --output-dir results \
    --archive results/test_data/numeric_5.zip \
    --charset digits --min-len 5 --max-len 5 \
    --thread-counts 1,2,4,6,8,10
```

GPU-ускоренный перебор:
```bash
./build/zipbrute --gpu \
    --archive results/test_data/numeric_5.zip \
    --charset digits --min-len 5 --max-len 5
```

Автоматический бенчмарк (CPU + GPU, 3 повтора):
```bash
./build/zipbrute --benchmark --mode both --repeat 3 --output-dir results/full
```
