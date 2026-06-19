# Входные и выходные данные

## Входные данные (командная строка)

| Параметр | Тип | По умолчанию | Описание |
|----------|-----|-------------|----------|
| `--archive` | string | — | Путь к тестовому ZIP-архиву |
| `--output-dir` | string | results | Каталог для результатов |
| `--charset` | string | digits | Алфавит: digits, lowercase, alphanum |
| `--min-len` | int | 1 | Минимальная длина пароля |
| `--max-len` | int | 5 | Максимальная длина пароля (≤ 5) |
| `--threads` | int/auto | auto | Количество потоков |
| `--thread-counts` | string | — | Список количества потоков через запятую |
| `--matrix` | flag | false | Запуск матрицы экспериментов |
| `--skip-test-suite` | flag | false | Пропустить создание тестовых архивов |
| `--source-file` | string | — | Исходный файл для тестовых архивов |

## Входные данные (тестовые архивы)

8 тестовых ZIP-архивов, создаваемых автоматически:

| Имя | Пароль | Алфавит | Длина | Защита |
|-----|--------|---------|-------|--------|
| numeric_4.zip | 4821 | digits | 4 | ZipCrypto |
| numeric_5.zip | 83920 | digits | 5 | ZipCrypto |
| lowercase_4.zip | hjkd | lowercase | 4 | ZipCrypto |
| lowercase_5.zip | qwert | lowercase | 5 | ZipCrypto |
| alphanum_4.zip | a1b2 | alphanum | 4 | ZipCrypto |
| alphanum_5.zip | a1b2c | alphanum | 5 | ZipCrypto |
| aes256_4.zip | x9yz | alphanum | 4 | AES-256 |
| aes256_5.zip | x9yz2 | alphanum | 5 | AES-256 |

## Выходные данные

### SQLite база данных (`results/experiments.db`)

Таблица `experiments` с полями: id, timestamp, archive_name, archive_path,
archive_size_bytes, protection_type, charset_name, charset_size,
password_length, total_space_size, num_threads, total_checks,
total_time_ms, checks_per_second, cpu_load_percent,
memory_resident_bytes, memory_virtual_bytes, compiler_flags,
cpu_model, password_found, found_password.

### CSV файл (`results/results.csv`)

Те же поля в формате CSV для импорта в Python/Excel.

### PDF отчёт (`results/report.pdf`)

Содержит:
- Таблицу сводных результатов
- График скорости проверки по алфавитам
- График зависимости времени от длины пароля
- График масштабирования производительности от числа потоков
- График сравнения ZipCrypto vs AES-256
