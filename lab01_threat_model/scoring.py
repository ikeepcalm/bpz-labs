# scoring.py - оцінювання переліку загроз (ЛР1, варіант 5)
from cvss import base_score

threats = {
    "T-01": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N",  # E1 S
    "T-02": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N",  # E1 R
    "T-03": "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:N/I:L/A:N",  # E1 R
    "T-04": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N",  # E2 R
    "T-05": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N",  # P1 S
    "T-06": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N",  # P1 R
    "T-07": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",  # P1 I
    "T-08": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",  # P1 D
    "T-09": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:H/A:N",  # P1 E
    "T-10": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N",  # P2 R
    "T-11": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",  # P2 I
    "T-12": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",  # P2 E
    "T-13": "CVSS:3.1/AV:A/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:N",  # D1 T
    "T-14": "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:H/A:N",  # D2 R
    "T-15": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N",  # F1 T
    "T-16": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H",  # F5/F6 D
}


def level(score: float) -> str:
    # Таблиця 2.3 методичних вказівок
    if score == 0:
        return "немає"
    if score < 4:
        return "низький"
    if score < 7:
        return "середній"
    if score < 9:
        return "високий"
    return "критичний"


if __name__ == "__main__":
    # контрольний вектор з методичних вказівок
    assert base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") == 9.8
    scores = {tid: base_score(v) for tid, v in threats.items()}
    for tid, s in scores.items():
        mark = "  ВИСОКИЙ РИЗИК" if s >= 7.0 else ""
        print(f"{tid}  {s:4}  {level(s):10}{mark}")
    high = [tid for tid, s in scores.items() if s >= 7.0]
    print(f"\nусього загроз: {len(scores)}, з оцінкою >= 7.0: {len(high)}")
    print("найкритичніша:", max(scores, key=scores.get))
    assert len(scores) >= 12 and len(high) >= 3  # min_threats, min_high_risk
