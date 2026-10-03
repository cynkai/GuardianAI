"""CSV and PDF report export."""

import io
from datetime import datetime

from .config import VERDICT_META
from .scoring import cve_table

try:
    from fpdf import FPDF
    HAS_FPDF = True
except ImportError:
    HAS_FPDF = False


# The PDF uses fpdf's core Helvetica font, which only covers latin-1. Map common
# typographic characters to ASCII first so they don't degrade to "?".
_PDF_ASCII = str.maketrans({"—": "-", "–": "-", "→": "->", "←": "<-", "…": "...",
                            "‘": "'", "’": "'", "“": '"', "”": '"', "·": "|", "•": "-"})


def _safe(s, n=200):
    return str(s).translate(_PDF_ASCII)[:n].encode("latin-1","replace").decode("latin-1")


class RedTeamPDF(FPDF if HAS_FPDF else object):
    R=(220,50,50); DARK=(20,20,20); D2=(35,35,35); LT=(220,220,220); GR=(140,140,140)

    def header(self):
        self.set_fill_color(*self.DARK); self.rect(0,0,210,14,"F")
        self.set_font("Helvetica","B",8); self.set_text_color(*self.R)
        self.set_xy(0,3); self.cell(0,6,"RED TEAM AI v7.0  |  CONFIDENTIAL",align="C")
        self.set_text_color(*self.GR); self.set_font("Helvetica","",7)
        self.set_xy(0,9); self.cell(0,4,"CMUX x AIM Hackathon 2025  |  AI Safety & Security",align="C")
        self.ln(10)

    def footer(self):
        self.set_y(-12); self.set_fill_color(*self.DARK); self.rect(0,self.get_y(),210,12,"F")
        self.set_font("Helvetica","I",7); self.set_text_color(*self.GR)
        self.cell(0,8,f"Page {self.page_no()}/{{nb}}  |  {datetime.now().strftime('%Y-%m-%d %H:%M')}  |  Confidential",align="C")

    def stitle(self, t):
        self.ln(3); self.set_fill_color(*self.D2); self.set_font("Helvetica","B",10)
        self.set_text_color(*self.R); self.cell(0,7,f"  {t}",ln=True,fill=True); self.ln(2)

    def kv(self, k, v, bold=False):
        self.set_font("Helvetica","B",9); self.set_text_color(*self.GR); self.cell(52,5,k,ln=False)
        self.set_font("Helvetica","B" if bold else "",9); self.set_text_color(*self.LT)
        self.cell(0,5,_safe(v),ln=True)


def generate_pdf(df, kpis, target_model, sp, after_df=None, delta=None):
    if not HAS_FPDF: return b""
    pdf = RedTeamPDF()
    pdf.alias_nb_pages()
    pdf.set_auto_page_break(auto=True, margin=18)
    pdf.set_margins(14,18,14)

    # Cover
    pdf.add_page()
    pdf.set_fill_color(*RedTeamPDF.DARK); pdf.rect(0,18,210,80,"F")
    pdf.set_xy(0,30); pdf.set_font("Helvetica","B",26)
    pdf.set_text_color(*RedTeamPDF.R); pdf.cell(0,12,"RED TEAM AI",align="C",ln=True)
    pdf.set_font("Helvetica","",12); pdf.set_text_color(*RedTeamPDF.LT)
    pdf.cell(0,7,"LLM Automated Red-Teaming Security Assessment v7.0",align="C",ln=True)
    pdf.set_font("Helvetica","I",8); pdf.set_text_color(*RedTeamPDF.GR)
    pdf.cell(0,5,"CMUX x AIM Hackathon 2025  |  OWASP LLM Top 10 (2025)  |  MITRE ATLAS",align="C",ln=True)
    gc = {"A":(40,180,80),"B":(52,199,89),"C":(255,149,0),"D":(255,107,0),"F":(255,59,48)}\
           .get(kpis.get("grade","F"),(100,100,100))
    pdf.set_xy(80,74); pdf.set_fill_color(*gc)
    pdf.set_font("Helvetica","B",34); pdf.set_text_color(255,255,255)
    pdf.cell(50,18,kpis.get("grade","F"),align="C",fill=True,ln=True)
    pdf.set_xy(0,93); pdf.set_font("Helvetica","",9); pdf.set_text_color(*RedTeamPDF.LT)
    pdf.cell(0,6,f"Security Score: {kpis.get('score',0)}/100",align="C",ln=True)
    pdf.ln(16)
    for lbl,val in [("Report Date",datetime.now().strftime("%Y-%m-%d %H:%M")),
                    ("Target Model",target_model),("Tests",str(kpis.get("n",0))),
                    ("Breach Rate",f"{kpis.get('vuln_rt',0)}%"),
                    ("Avg CVSS",str(kpis.get("avg_cvss",kpis.get("avg_sev",0)))),
                    ("CVE IDs Issued",str(int((df.get("CVE ID","") != "N/A").sum()) if "CVE ID" in df.columns else 0)),
                    ("Classification","CONFIDENTIAL — Authorised Red-Team Use Only")]:
        pdf.kv(lbl,val)

    # Exec Summary
    pdf.add_page(); pdf.stitle("1. Executive Summary")
    for k,v in [("VULNERABLE",str(kpis.get("vuln",0))),("PARTIAL",str(kpis.get("partial",0))),
                ("SAFE",str(kpis.get("safe",0))),("Critical Hits",str(kpis.get("crit_hit",0))),
                ("Breach Rate",f"{kpis.get('vuln_rt',0)}%"),
                ("Avg Severity",f"{kpis.get('avg_sev',0)}/10"),
                ("Score",f"{kpis.get('score',0)}/100  Grade {kpis.get('grade','F')}")]:
        pdf.kv(k,v,bold=(k=="Score"))

    if delta:
        pdf.ln(3); pdf.stitle("2. Hardening Delta (Before vs After)")
        b,a = delta["before"],delta["after"]
        for k,bv,av,dv in [
            ("Security Score",str(b["score"]),str(a["score"]),f"{delta['score_delta']:+d}"),
            ("Breach Rate",f"{b['vuln_rt']}%",f"{a['vuln_rt']}%",f"{delta['rate_delta']:+.1f}%"),
        ]:
            pdf.set_font("Helvetica","B",9); pdf.set_text_color(*RedTeamPDF.GR); pdf.cell(45,5,k,ln=False)
            pdf.set_font("Helvetica","",9); pdf.set_text_color(*RedTeamPDF.LT)
            pdf.cell(30,5,_safe(f"{bv} → {av}"),ln=False)
            cl = (40,180,80) if (delta["score_delta"]>0 and k=="Security Score") else (220,50,50)
            pdf.set_text_color(*cl); pdf.set_font("Helvetica","B",9); pdf.cell(0,5,dv,ln=True)

    # CVE Index
    sec=3; pdf.add_page(); pdf.stitle(f"{sec}. CVE Finding Index")
    cve = cve_table(df)
    pdf.set_fill_color(*RedTeamPDF.D2); pdf.set_font("Helvetica","B",7); pdf.set_text_color(*RedTeamPDF.R)
    for col,w in [("CVE ID",28),("ID",16),("Category",42),("Risk",16),("Verdict",24),("CVSS",18),("Sev",16)]:
        pdf.cell(w,6,col,fill=True,border=0,ln=False)
    pdf.ln(6)
    for _,row in cve.iterrows():
        if pdf.get_y()>260: pdf.add_page()
        pdf.set_font("Helvetica","B",7); pdf.set_text_color(*RedTeamPDF.R)
        pdf.cell(28,5,_safe(row.get("CVE ID",""),12),ln=False)
        pdf.set_text_color(*RedTeamPDF.LT); pdf.set_font("Helvetica","",7)
        pdf.cell(16,5,_safe(row.get("ID",""),8),ln=False)
        pdf.cell(42,5,_safe(row.get("Category",""),26),ln=False)
        pdf.cell(16,5,_safe(row.get("Risk Level",""),8),ln=False)
        v=str(row.get("Verdict","ERROR"))
        rgb=VERDICT_META.get(v,{"rgb":(100,100,100)})["rgb"]
        pdf.set_fill_color(*rgb); pdf.set_text_color(255,255,255); pdf.set_font("Helvetica","B",6)
        pdf.cell(24,5,v,fill=True,ln=False)
        pdf.set_text_color(*RedTeamPDF.LT); pdf.set_font("Helvetica","",7)
        pdf.cell(18,5,str(row.get("CVSS Score","")),ln=False)
        pdf.cell(16,5,str(row.get("Severity Score","")),ln=True)

    # Detailed Findings
    sec+=1; pdf.add_page(); pdf.stitle(f"{sec}. Detailed Findings")
    for _,row in cve.iterrows():
        if pdf.get_y()>240: pdf.add_page()
        pdf.set_fill_color(*RedTeamPDF.D2); pdf.set_font("Helvetica","B",8)
        pdf.set_text_color(*RedTeamPDF.R)
        pdf.cell(0,6,_safe(f"  {row.get('CVE ID','?')} — {_safe(row.get('Technique',''),55)}"),fill=True,ln=True)
        for k,v in [("Attack ID",row.get("ID","")),("OWASP",row.get("OWASP Ref","")),
                    ("CVSS Score",f"{row.get('CVSS Score',0)} ({row.get('CVSS Label','')})"),
                    ("Evidence",row.get("Evidence","")),("Reasoning",row.get("Reasoning","")),
                    ("Remediation",row.get("Remediation",""))]:
            pdf.set_font("Helvetica","B",7); pdf.set_text_color(*RedTeamPDF.GR); pdf.cell(30,4,str(k),ln=False)
            pdf.set_font("Helvetica","",7); pdf.set_text_color(*RedTeamPDF.LT)
            pdf.multi_cell(0,4,_safe(str(v),160))
            pdf.set_x(pdf.l_margin)  # fpdf2 leaves x at the right edge after multi_cell
        pdf.ln(2)

    return bytes(pdf.output())


def df_to_csv(df):
    buf=io.StringIO(); df.to_csv(buf,index=False); return buf.getvalue().encode()
