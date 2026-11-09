"""Synthetic source data. Every name, tax id and note is invented.

24 suppliers: 8 compliance notes mention an investigation, 6 mention
something else and 10 are NULL. tax_id, compliance_note and risk_score are
masked for any identity without the unmasking role (see 10_core.sql).
"""

from __future__ import annotations

from .db import q

NAMES = ["Alpha", "Beta", "Gamma", "Delta", "Epsilon", "Zeta", "Eta", "Theta", "Iota", "Kappa", "Lambda", "Mu",
         "Nu", "Xi", "Omicron", "Pi", "Rho", "Sigma", "Tau", "Upsilon", "Phi", "Chi", "Psi", "Omega"]
REGIONS = ["NORTH", "SOUTH", "EAST"]
CATALOG = [
    ("Industrial valves", "Gate, ball and check valves; stainless steel pipe fittings; pressure testing"),
    ("Packaging", "Corrugated boxes, pallet wrap and custom foam inserts for fragile goods"),
    ("Cold-chain logistics", "Refrigerated trucking and temperature-monitored warehousing for food and pharma"),
    ("Cloud hosting", "Managed virtual machines, backups and 24x7 monitoring for business applications"),
    ("Facilities cleaning", "Office cleaning, waste sorting and window washing on weekly contracts"),
    ("Electrical components", "Cables, circuit breakers and industrial connectors with same-week delivery"),
    ("Office supplies", "Paper, toner, desks and ergonomic chairs delivered to regional offices"),
    ("Freight forwarding", "Sea and air freight booking, customs paperwork and port pickup"),
    ("Steel fabrication", "Laser cutting, welding and powder coating of steel frames and brackets"),
    ("Laboratory equipment", "Pipettes, centrifuges and calibration services for quality labs"),
    ("Security services", "Guarded reception, access badges and CCTV maintenance"),
    ("Printing", "Labels, manuals and large-format posters printed on demand"),
]
INVESTIGATION = {
    3: "Synthetic review: duplicate bank account under investigation (case SYN-CR-0003)",
    5: "Synthetic review: invoice split pattern under investigation (case SYN-CR-0005)",
    8: "Synthetic review: sanctions screening hit under investigation (case SYN-CR-0008)",
    11: "Synthetic review: conflict of interest under investigation (case SYN-CR-0011)",
    14: "Synthetic review: price inflation report under investigation (case SYN-CR-0014)",
    17: "Synthetic review: shell company indicators under investigation (case SYN-CR-0017)",
    20: "Synthetic review: kickback allegation under investigation (case SYN-CR-0020)",
    23: "Synthetic review: falsified certificate under investigation (case SYN-CR-0023)",
}
OTHER = {
    1: "Synthetic review: insurance certificate renewal pending",
    6: "Synthetic review: onboarding documents complete",
    9: "Synthetic review: late delivery penalty applied in 2025",
    13: "Synthetic review: preferred supplier status granted",
    18: "Synthetic review: bank details verified by call-back",
    22: "Synthetic review: annual audit closed without remarks",
}
MASKED = {"suppliers": ["tax_id", "compliance_note", "risk_score"]}
TABLES = {  # table -> (primary key, columns in order)
    "suppliers": ("supplier_id", ["supplier_id", "supplier_name", "region", "category", "capabilities",
                                  "tax_id", "compliance_note", "risk_score"]),
    "invoices": ("invoice_id", ["invoice_id", "supplier_id", "amount", "issue_date"]),
}


def suppliers() -> list[tuple]:
    rows = []
    for i, name in enumerate(NAMES, start=1):
        region = REGIONS[(i - 1) % 3]
        category, capabilities = CATALOG[(i - 1) % len(CATALOG)]
        note = INVESTIGATION.get(i, OTHER.get(i))
        risk = 70 + (i * 7) % 29 if i in INVESTIGATION else 5 + (i * 11) % 47
        rows.append((i, f"Synthetic Supplier {name}", region, category, capabilities,
                     f"SYN-TX-{region[0]}-{i:04d}", note, risk))
    return rows


def invoices() -> list[tuple]:
    rows, invoice_id = [], 1000
    for i in range(1, len(NAMES) + 1):
        for k in range(2 + i % 3):
            invoice_id += 1
            cents = (i * 37 + k * 53) % 100
            amount = f"{1000 + (i * 137 + k * 911) % 9000}.{cents:02d}"
            rows.append((invoice_id, i, amount, f"2026-{1 + (i + k) % 9:02d}-{1 + (i * 3 + k * 5) % 28:02d}"))
    return rows


def insert_sql(supplier_rows: list[tuple] | None = None, invoice_rows: list[tuple] | None = None) -> str:
    srows = suppliers() if supplier_rows is None else supplier_rows
    irows = invoices() if invoice_rows is None else invoice_rows
    return "\n".join([
        "INSERT INTO m1_src.suppliers VALUES\n  " + ",\n  ".join(
            "(" + ", ".join(q(v) for v in r) + ")" for r in srows) + ";",
        "INSERT INTO m1_src.invoices VALUES\n  " + ",\n  ".join(
            f"({r[0]}, {r[1]}, {r[2]}, {q(r[3])})" for r in irows) + ";",
    ])
