import customtkinter as ctk
import tkinter as tk
from tkinter import filedialog, ttk
import pandas as pd
import numpy as np
import pickle
from pathlib import Path
from collections import Counter
import threading
import sys
import os

# ==============================
# LOAD MODEL
# ==============================

BASE_DIR  = Path(__file__).resolve().parent
MODEL_DIR = BASE_DIR / "models"

with open(MODEL_DIR / "rf_model.pkl", "rb") as f:
    model = pickle.load(f)

with open(MODEL_DIR / "label_encoder.pkl", "rb") as f:
    le = pickle.load(f)

with open(MODEL_DIR / "feature_cols.pkl", "rb") as f:
    feature_cols = pickle.load(f)

# ==============================
# CONFIG
# ==============================

SEVERITY = {
    "BENIGN":     {"level": "NONE",     "color": "#22c55e", "score": 0},
    "BruteForce": {"level": "HIGH",     "color": "#f97316", "score": 3},
    "DDoS":       {"level": "CRITICAL", "color": "#ef4444", "score": 4},
    "PortScan":   {"level": "MEDIUM",   "color": "#f59e0b", "score": 2},
    "WebAttack":  {"level": "HIGH",     "color": "#f97316", "score": 3},
}

DESCRIPTIONS = {
    "BENIGN":     "Normal network traffic. No threats detected.",
    "DDoS":       "DDoS attack detected. Attacker flooding network to overwhelm services.",
    "PortScan":   "Port scanning detected. Attacker probing for open ports and services.",
    "BruteForce": "Brute force attack detected. Repeated login attempts to guess credentials.",
    "WebAttack":  "Web attack detected. SQL injection, XSS, or web brute force activity.",
}

RECOMMENDATIONS = {
    "BENIGN":     ["Continue monitoring traffic normally", "Maintain regular security audits"],
    "DDoS":       ["Enable rate limiting immediately", "Block source IPs at firewall", "Contact ISP for upstream filtering", "Enable CDN/DDoS protection"],
    "PortScan":   ["Block scanning source IP", "Review and close unnecessary ports", "Enable port scan detection alerts", "Check if scan preceded intrusion"],
    "BruteForce": ["Block attacking IP immediately", "Enable account lockout policy", "Implement multi-factor authentication", "Rotate potentially compromised credentials"],
    "WebAttack":  ["Block attacking IP at WAF", "Review web application firewall rules", "Check logs for successful exploitation", "Update and patch web application"],
}


# ==============================
# APP
# ==============================

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")


class NetworkAIApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("Network Intrusion Detection AI")
        self.geometry("1400x860")
        self.minsize(1100, 700)
        self.configure(fg_color="#080c14")

        self.result_data = None
        self._build_ui()

    # ==============================
    # UI BUILDER
    # ==============================

    def _build_ui(self):
        # ── NAV BAR ──
        nav = ctk.CTkFrame(self, fg_color="#0d1421", corner_radius=0, height=56)
        nav.pack(fill="x", side="top")
        nav.pack_propagate(False)

        ctk.CTkLabel(
            nav, text="  Network Intrusion Detection AI",
            font=ctk.CTkFont(size=16, weight="bold"),
            text_color="#38bdf8"
        ).pack(side="left", padx=20)

        ctk.CTkLabel(
            nav, text="Random Forest · CICIDS2017 · 5 Classes",
            font=ctk.CTkFont(size=12),
            text_color="#64748b"
        ).pack(side="right", padx=20)

        # ── MAIN LAYOUT ──
        main = ctk.CTkFrame(self, fg_color="transparent")
        main.pack(fill="both", expand=True, padx=16, pady=12)

        # left panel — upload + summary
        self.left = ctk.CTkFrame(main, fg_color="transparent", width=320)
        self.left.pack(side="left", fill="y", padx=(0, 10))
        self.left.pack_propagate(False)

        # right panel — details
        self.right = ctk.CTkFrame(main, fg_color="transparent")
        self.right.pack(side="left", fill="both", expand=True)

        self._build_left()
        self._build_right()

    def _build_left(self):
        # ── UPLOAD CARD ──
        upload_card = ctk.CTkFrame(self.left, fg_color="#111927", corner_radius=12)
        upload_card.pack(fill="x", pady=(0, 10))

        ctk.CTkLabel(
            upload_card,
            text="Upload Network Log",
            font=ctk.CTkFont(size=14, weight="bold"),
            text_color="#e2e8f0"
        ).pack(anchor="w", padx=16, pady=(14, 4))

        ctk.CTkLabel(
            upload_card,
            text="CSV file with network flow features",
            font=ctk.CTkFont(size=12),
            text_color="#64748b"
        ).pack(anchor="w", padx=16, pady=(0, 12))

        self.file_label = ctk.CTkLabel(
            upload_card,
            text="No file selected",
            font=ctk.CTkFont(size=12),
            text_color="#64748b",
            wraplength=260
        )
        self.file_label.pack(padx=16, pady=(0, 8))

        ctk.CTkButton(
            upload_card,
            text="Browse CSV File",
            command=self._browse_file,
            fg_color="#1e3a5f",
            hover_color="#1e4a7f",
            text_color="#38bdf8",
            corner_radius=8,
            height=36
        ).pack(fill="x", padx=16, pady=(0, 8))

        self.analyze_btn = ctk.CTkButton(
            upload_card,
            text="Analyze",
            command=self._run_analysis,
            fg_color="#38bdf8",
            hover_color="#0ea5e9",
            text_color="#042c53",
            corner_radius=8,
            height=40,
            font=ctk.CTkFont(size=14, weight="bold")
        )
        self.analyze_btn.pack(fill="x", padx=16, pady=(0, 16))

        # ── STATUS ──
        self.status_label = ctk.CTkLabel(
            self.left,
            text="",
            font=ctk.CTkFont(size=12),
            text_color="#64748b"
        )
        self.status_label.pack(pady=(0, 10))

        # ── THREAT SUMMARY CARD ──
        self.summary_card = ctk.CTkFrame(self.left, fg_color="#111927", corner_radius=12)
        self.summary_card.pack(fill="x", pady=(0, 10))

        ctk.CTkLabel(
            self.summary_card,
            text="Threat Summary",
            font=ctk.CTkFont(size=14, weight="bold"),
            text_color="#e2e8f0"
        ).pack(anchor="w", padx=16, pady=(14, 10))

        self.threat_label = ctk.CTkLabel(
            self.summary_card,
            text="—",
            font=ctk.CTkFont(size=28, weight="bold"),
            text_color="#64748b"
        )
        self.threat_label.pack(padx=16, pady=(0, 4))

        self.severity_label = ctk.CTkLabel(
            self.summary_card,
            text="No analysis yet",
            font=ctk.CTkFont(size=12),
            text_color="#64748b"
        )
        self.severity_label.pack(padx=16, pady=(0, 10))

        # stats row
        stats_frame = ctk.CTkFrame(self.summary_card, fg_color="transparent")
        stats_frame.pack(fill="x", padx=16, pady=(0, 14))

        self.total_label  = self._stat_box(stats_frame, "Total Flows", "—")
        self.attack_label = self._stat_box(stats_frame, "Attacks", "—")
        self.benign_label = self._stat_box(stats_frame, "Benign", "—")

        # ── DESCRIPTION CARD ──
        self.desc_card = ctk.CTkFrame(self.left, fg_color="#111927", corner_radius=12)
        self.desc_card.pack(fill="x", pady=(0, 10))

        ctk.CTkLabel(
            self.desc_card,
            text="Description",
            font=ctk.CTkFont(size=14, weight="bold"),
            text_color="#e2e8f0"
        ).pack(anchor="w", padx=16, pady=(14, 6))

        self.desc_label = ctk.CTkLabel(
            self.desc_card,
            text="Upload a CSV file to begin analysis.",
            font=ctk.CTkFont(size=12),
            text_color="#64748b",
            wraplength=270,
            justify="left"
        )
        self.desc_label.pack(anchor="w", padx=16, pady=(0, 14))

        # ── RECOMMENDATIONS ──
        self.rec_card = ctk.CTkFrame(self.left, fg_color="#111927", corner_radius=12)
        self.rec_card.pack(fill="both", expand=True)

        ctk.CTkLabel(
            self.rec_card,
            text="Recommendations",
            font=ctk.CTkFont(size=14, weight="bold"),
            text_color="#e2e8f0"
        ).pack(anchor="w", padx=16, pady=(14, 6))

        self.rec_frame = ctk.CTkScrollableFrame(
            self.rec_card, fg_color="transparent", height=120
        )
        self.rec_frame.pack(fill="both", expand=True, padx=8, pady=(0, 12))

    def _stat_box(self, parent, label, value):
        frame = ctk.CTkFrame(parent, fg_color="#0d1421", corner_radius=8)
        frame.pack(side="left", expand=True, fill="x", padx=3)

        val_lbl = ctk.CTkLabel(
            frame, text=value,
            font=ctk.CTkFont(size=18, weight="bold"),
            text_color="#38bdf8"
        )
        val_lbl.pack(pady=(8, 0))

        ctk.CTkLabel(
            frame, text=label,
            font=ctk.CTkFont(size=10),
            text_color="#64748b"
        ).pack(pady=(0, 8))

        return val_lbl

    def _build_right(self):
        # ── TOP METRICS ROW ──
        metrics_row = ctk.CTkFrame(self.right, fg_color="transparent")
        metrics_row.pack(fill="x", pady=(0, 10))

        self.metric_cards = {}
        for name in ["BENIGN", "BruteForce", "DDoS", "PortScan"]:
            card = ctk.CTkFrame(metrics_row, fg_color="#111927", corner_radius=12)
            card.pack(side="left", expand=True, fill="x", padx=5)

            color = SEVERITY.get(name, {}).get("color", "#64748b")

            pct_lbl = ctk.CTkLabel(
                card, text="0%",
                font=ctk.CTkFont(size=22, weight="bold"),
                text_color=color
            )
            pct_lbl.pack(pady=(12, 2))

            ctk.CTkLabel(
                card, text=name,
                font=ctk.CTkFont(size=12),
                text_color="#64748b"
            ).pack(pady=(0, 12))

            self.metric_cards[name] = pct_lbl

        # ── TABS ──
        self.tab_view = ctk.CTkTabview(
            self.right,
            fg_color="#111927",
            segmented_button_fg_color="#0d1421",
            segmented_button_selected_color="#1e3a5f",
            segmented_button_selected_hover_color="#1e4a7f",
            segmented_button_unselected_color="#0d1421",
            segmented_button_unselected_hover_color="#111927",
            text_color="#38bdf8",
            corner_radius=12
        )
        self.tab_view.pack(fill="both", expand=True)

        self.tab_view.add("Flow Analysis")
        self.tab_view.add("Attack Breakdown")
        self.tab_view.add("Feature Importance")

        self._build_flow_tab()
        self._build_breakdown_tab()
        self._build_importance_tab()

    def _build_flow_tab(self):
        tab = self.tab_view.tab("Flow Analysis")

        # search bar
        search_frame = ctk.CTkFrame(tab, fg_color="transparent")
        search_frame.pack(fill="x", padx=10, pady=(10, 6))

        ctk.CTkLabel(
            search_frame, text="Filter:",
            font=ctk.CTkFont(size=12),
            text_color="#64748b"
        ).pack(side="left", padx=(0, 8))

        self.filter_var = tk.StringVar()
        self.filter_var.trace("w", self._filter_flows)

        ctk.CTkEntry(
            search_frame,
            textvariable=self.filter_var,
            placeholder_text="Filter by attack type...",
            fg_color="#0d1421",
            border_color="#1e3a5f",
            height=32,
            width=200
        ).pack(side="left")

        self.flow_count_label = ctk.CTkLabel(
            search_frame,
            text="",
            font=ctk.CTkFont(size=12),
            text_color="#64748b"
        )
        self.flow_count_label.pack(side="right", padx=10)

        # table
        table_frame = ctk.CTkFrame(tab, fg_color="transparent")
        table_frame.pack(fill="both", expand=True, padx=10, pady=(0, 10))

        style = ttk.Style()
        style.theme_use("clam")
        style.configure(
            "Dark.Treeview",
            background="#0d1421",
            foreground="#e2e8f0",
            rowheight=28,
            fieldbackground="#0d1421",
            borderwidth=0,
            font=("Inter", 11)
        )
        style.configure(
            "Dark.Treeview.Heading",
            background="#111927",
            foreground="#38bdf8",
            relief="flat",
            font=("Inter", 11, "bold")
        )
        style.map(
            "Dark.Treeview",
            background=[("selected", "#1e3a5f")],
            foreground=[("selected", "#38bdf8")]
        )

        self.tree = ttk.Treeview(
            table_frame,
            columns=("flow", "prediction", "confidence", "severity"),
            show="headings",
            style="Dark.Treeview"
        )

        self.tree.heading("flow",       text="Flow #")
        self.tree.heading("prediction", text="Prediction")
        self.tree.heading("confidence", text="Confidence")
        self.tree.heading("severity",   text="Severity")

        self.tree.column("flow",       width=80,  anchor="center")
        self.tree.column("prediction", width=150, anchor="center")
        self.tree.column("confidence", width=120, anchor="center")
        self.tree.column("severity",   width=120, anchor="center")

        scrollbar = ttk.Scrollbar(table_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)

        self.tree.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        # tag colors
        self.tree.tag_configure("BENIGN",     foreground="#22c55e")
        self.tree.tag_configure("BruteForce", foreground="#f97316")
        self.tree.tag_configure("DDoS",       foreground="#ef4444")
        self.tree.tag_configure("PortScan",   foreground="#f59e0b")
        self.tree.tag_configure("WebAttack",  foreground="#f97316")

    def _build_breakdown_tab(self):
        tab = self.tab_view.tab("Attack Breakdown")

        self.breakdown_frame = ctk.CTkScrollableFrame(
            tab, fg_color="transparent"
        )
        self.breakdown_frame.pack(fill="both", expand=True, padx=10, pady=10)

        self.breakdown_label = ctk.CTkLabel(
            self.breakdown_frame,
            text="No data yet. Upload a CSV to analyze.",
            font=ctk.CTkFont(size=13),
            text_color="#64748b"
        )
        self.breakdown_label.pack(pady=40)

    def _build_importance_tab(self):
        tab = self.tab_view.tab("Feature Importance")

        self.importance_frame = ctk.CTkScrollableFrame(
            tab, fg_color="transparent"
        )
        self.importance_frame.pack(fill="both", expand=True, padx=10, pady=10)

        importances = sorted(
            zip(feature_cols, model.feature_importances_),
            key=lambda x: x[1], reverse=True
        )[:15]

        max_imp = importances[0][1]

        ctk.CTkLabel(
            self.importance_frame,
            text="Top 15 Features Used by Model",
            font=ctk.CTkFont(size=13, weight="bold"),
            text_color="#e2e8f0"
        ).pack(anchor="w", pady=(0, 12))

        for feat, imp in importances:
            row = ctk.CTkFrame(self.importance_frame, fg_color="transparent")
            row.pack(fill="x", pady=3)

            ctk.CTkLabel(
                row,
                text=feat.strip()[:35],
                font=ctk.CTkFont(size=11),
                text_color="#94a3b8",
                width=220,
                anchor="w"
            ).pack(side="left")

            bar_bg = ctk.CTkFrame(row, fg_color="#0d1421", corner_radius=4, height=16)
            bar_bg.pack(side="left", fill="x", expand=True, padx=8)
            bar_bg.pack_propagate(False)

            bar_w = max(4, int((imp / max_imp) * 300))
            bar = ctk.CTkFrame(bar_bg, fg_color="#38bdf8", corner_radius=4, width=bar_w)
            bar.pack(side="left", fill="y")

            ctk.CTkLabel(
                row,
                text=f"{imp:.4f}",
                font=ctk.CTkFont(size=11),
                text_color="#64748b",
                width=60
            ).pack(side="right")

    # ==============================
    # ACTIONS
    # ==============================

    def _browse_file(self):
        path = filedialog.askopenfilename(
            title="Select Network Log CSV",
            filetypes=[("CSV Files", "*.csv"), ("All Files", "*.*")]
        )
        if path:
            self.file_path = path
            self.file_label.configure(
                text=Path(path).name,
                text_color="#38bdf8"
            )

    def _run_analysis(self):
        if not hasattr(self, "file_path"):
            self.status_label.configure(
                text="Please select a CSV file first",
                text_color="#ef4444"
            )
            return

        self.analyze_btn.configure(state="disabled", text="Analyzing...")
        self.status_label.configure(text="Processing...", text_color="#64748b")

        thread = threading.Thread(target=self._analyze_thread)
        thread.daemon = True
        thread.start()

    def _analyze_thread(self):
        try:
            df = pd.read_csv(
                self.file_path,
                encoding="utf-8",
                encoding_errors="replace"
            )

            # drop label column if present
            for col in [" Label", "Label", "label"]:
                if col in df.columns:
                    df = df.drop(columns=[col])

            missing = [c for c in feature_cols if c not in df.columns]
            for col in missing:
                df[col] = 0

            X = df[feature_cols].copy()
            X.replace([np.inf, -np.inf], np.nan, inplace=True)
            X.fillna(0, inplace=True)

            preds       = model.predict(X)
            probs       = model.predict_proba(X)
            labels      = le.inverse_transform(preds)
            label_names = list(le.classes_)

            flows = []
            for i, (label, prob) in enumerate(zip(labels, probs)):
                flows.append({
                    "flow":       i + 1,
                    "prediction": label,
                    "confidence": round(float(prob.max()) * 100, 1),
                    "severity":   SEVERITY.get(label, {}).get("level", "UNKNOWN"),
                })

            counts     = Counter(labels)
            attacks    = {k: v for k, v in counts.items() if k != "BENIGN"}
            total      = len(labels)
            top_attack = max(
                attacks, key=lambda k: SEVERITY.get(k, {}).get("score", 0)
            ) if attacks else "BENIGN"

            scores = {
                name: round(float(probs[:, i].mean()) * 100, 2)
                for i, name in enumerate(label_names)
            }

            self.result_data = {
                "total":      total,
                "benign":     counts.get("BENIGN", 0),
                "attacks":    total - counts.get("BENIGN", 0),
                "counts":     dict(counts),
                "top_attack": top_attack,
                "flows":      flows,
                "scores":     scores,
            }

            self.after(0, self._update_ui)

        except Exception as e:
            self.after(0, lambda: self.status_label.configure(
                text=f"Error: {str(e)}", text_color="#ef4444"
            ))
            self.after(0, lambda: self.analyze_btn.configure(
                state="normal", text="Analyze"
            ))

    def _update_ui(self):
        d          = self.result_data
        top        = d["top_attack"]
        sev        = SEVERITY.get(top, {})
        color      = sev.get("color", "#64748b")
        sev_level  = sev.get("level", "NONE")

        # summary
        self.threat_label.configure(text=top, text_color=color)
        self.severity_label.configure(
            text=f"Severity: {sev_level}",
            text_color=color
        )
        self.total_label.configure(text=str(d["total"]))
        self.attack_label.configure(
            text=str(d["attacks"]),
            text_color="#ef4444" if d["attacks"] > 0 else "#22c55e"
        )
        self.benign_label.configure(text=str(d["benign"]))

        # description
        self.desc_label.configure(
            text=DESCRIPTIONS.get(top, ""),
            text_color="#94a3b8"
        )

        # recommendations
        for w in self.rec_frame.winfo_children():
            w.destroy()

        for rec in RECOMMENDATIONS.get(top, []):
            row = ctk.CTkFrame(self.rec_frame, fg_color="transparent")
            row.pack(fill="x", pady=2)

            ctk.CTkLabel(
                row, text="→",
                font=ctk.CTkFont(size=12),
                text_color="#38bdf8",
                width=20
            ).pack(side="left")

            ctk.CTkLabel(
                row, text=rec,
                font=ctk.CTkFont(size=11),
                text_color="#94a3b8",
                wraplength=240,
                justify="left"
            ).pack(side="left", padx=4)

        # metric cards
        scores = d["scores"]
        for name, lbl in self.metric_cards.items():
            pct = scores.get(name, 0)
            lbl.configure(text=f"{pct:.1f}%")

        # flow table
        for row in self.tree.get_children():
            self.tree.delete(row)

        self.all_flows = d["flows"]
        self._populate_table(self.all_flows)

        # breakdown tab
        for w in self.breakdown_frame.winfo_children():
            w.destroy()

        ctk.CTkLabel(
            self.breakdown_frame,
            text="Attack Type Breakdown",
            font=ctk.CTkFont(size=14, weight="bold"),
            text_color="#e2e8f0"
        ).pack(anchor="w", pady=(0, 12))

        total = d["total"]
        for attack, count in sorted(
            d["counts"].items(), key=lambda x: x[1], reverse=True
        ):
            pct   = (count / total) * 100
            color = SEVERITY.get(attack, {}).get("color", "#64748b")
            sev   = SEVERITY.get(attack, {}).get("level", "")

            row_frame = ctk.CTkFrame(
                self.breakdown_frame, fg_color="#0d1421", corner_radius=8
            )
            row_frame.pack(fill="x", pady=4)

            header = ctk.CTkFrame(row_frame, fg_color="transparent")
            header.pack(fill="x", padx=12, pady=(10, 4))

            ctk.CTkLabel(
                header,
                text=attack,
                font=ctk.CTkFont(size=13, weight="bold"),
                text_color=color
            ).pack(side="left")

            ctk.CTkLabel(
                header,
                text=f"{count:,} flows  ({pct:.1f}%)  [{sev}]",
                font=ctk.CTkFont(size=11),
                text_color="#64748b"
            ).pack(side="right")

            bar_bg = ctk.CTkFrame(
                row_frame, fg_color="#111927", corner_radius=4, height=10
            )
            bar_bg.pack(fill="x", padx=12, pady=(0, 10))
            bar_bg.pack_propagate(False)

            bar_w = max(4, int((pct / 100) * 400))
            ctk.CTkFrame(
                bar_bg, fg_color=color, corner_radius=4, width=bar_w
            ).pack(side="left", fill="y")

        # status
        self.status_label.configure(
            text=f"Analysis complete — {total:,} flows processed",
            text_color="#22c55e"
        )
        self.analyze_btn.configure(state="normal", text="Analyze")
        self.flow_count_label.configure(text=f"{len(d['flows'])} flows shown")

    def _populate_table(self, flows):
        for row in self.tree.get_children():
            self.tree.delete(row)

        for f in flows:
            self.tree.insert(
                "", "end",
                values=(
                    f["flow"],
                    f["prediction"],
                    f"{f['confidence']}%",
                    f["severity"]
                ),
                tags=(f["prediction"],)
            )

    def _filter_flows(self, *args):
        if not hasattr(self, "all_flows"):
            return

        query = self.filter_var.get().lower()
        filtered = [
            f for f in self.all_flows
            if query in f["prediction"].lower()
            or query in f["severity"].lower()
        ]
        self._populate_table(filtered)
        self.flow_count_label.configure(
            text=f"{len(filtered)} flows shown"
        )


# ==============================
# RUN
# ==============================

if __name__ == "__main__":
    app = NetworkAIApp()
    app.mainloop()