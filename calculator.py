# calculator.py
# Handles wordlist processing, pure brute-force space calculation, and attack time feasibility metrics
import config


def count_wordlist(path=None):
    """
    Reads a wordlist file and counts unique non-empty lines using a set.
    Defaults to config.DEFAULT_WORDLIST if no path is provided.
    """
    if not path or path.strip() == "":
        path = config.DEFAULT_WORDLIST

    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            unique_word = set(line.strip() for line in f if line.strip())
        return len(unique_word), path
    except FileNotFoundError:
        return None, path
    except Exception:
        return None, path


def calculate_brute_force(password_length, charset_key):
    """
    Calculates total possible combinations (N^L) using tuple unpacking from config.CHARSETS.
    Returns total combinations, charset size, and description.
    """
    if charset_key not in config.CHARSETS:
        charset_key = "2"

    charset_size, charset_description = config.CHARSETS[charset_key]
    combinations = charset_size ** password_length

    return combinations, charset_size, charset_description


def calculate_feasibility(total_tries, speed=None, max_hours=config.MAX_HOURS):
    if speed is None or speed <= 0:
        speed = config.DEFAULT_SPEED

    seconds = total_tries / speed
    minutes = seconds / 60        # ← أضف
    hours = seconds / 3600
    days = hours / 24
    feasible = hours <= max_hours

    return {
        "total_tries": total_tries,
        "speed_per_second": speed,
        "seconds_needed": round(seconds, 2),   # ← أضف
        "minutes_needed": round(minutes, 2),   # ← أضف
        "hours_needed": round(hours, 2),
        "days_needed": round(days, 2),
        "max_hours_allowed": max_hours,
        "feasible": feasible,
    }