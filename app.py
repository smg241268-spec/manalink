import base64
import datetime
import hashlib
import hmac
import html
import io
import json
import os
import re
import sqlite3
import time
from contextlib import closing

import requests
import streamlit as st
import streamlit.components.v1 as components
import google.generativeai as genai
from pypdf import PdfReader

try:
    import anthropic  # Claude API
except ImportError:  # 未インストールでもGeminiだけで動くようにする
    anthropic = None

try:
    from cryptography.fernet import Fernet, InvalidToken  # APIキーの暗号化
except ImportError:
    Fernet = None
    InvalidToken = Exception

try:
    import markdown as md_lib  # PDF／HTML出力用
except ImportError:
    md_lib = None

# =====================================================================
#  ManaLink ― URLとPDFを、学びに変える。
# =====================================================================
APP_NAME = "ManaLink"
APP_TAGLINE = "URLとPDFを、学びに変える。"

st.set_page_config(
    page_title=f"{APP_NAME}｜{APP_TAGLINE}",
    page_icon="🔗",
    layout="centered",
    initial_sidebar_state="expanded",
)

# ---------- デザイン（CSS） ----------
st.markdown(
    """
<style>
#MainMenu, footer {visibility: hidden;}
.block-container {max-width: 860px; padding-top: 2rem; padding-bottom: 4rem;}

/* 読みやすい文字 */
.stMarkdown p, .stMarkdown li {line-height: 1.9; font-size: 1.02rem;}
.stMarkdown li {margin-bottom: .45rem;}
.stMarkdown ol, .stMarkdown ul {padding-left: 1.3rem;}
section[data-testid="stSidebar"] .stMarkdown p,
section[data-testid="stSidebar"] .stMarkdown li {font-size: .95rem; line-height: 1.75;}

/* ヒーロー */
.hero {
    background: linear-gradient(135deg, #4f46e5 0%, #7c3aed 55%, #ec4899 100%);
    border-radius: 22px; padding: 30px 28px 26px; margin-bottom: 1.4rem;
    box-shadow: 0 12px 32px rgba(79, 70, 229, .28);
}
.hero-title {font-size: 2.3rem; font-weight: 800; letter-spacing: .02em; color: #fff; line-height: 1.2;}
.hero-sub {margin-top: .45rem; font-size: 1.02rem; color: rgba(255,255,255,.92); line-height: 1.6;}
.hero-chip {
    display: inline-block; margin-top: 14px; margin-right: 6px; padding: 4px 12px; border-radius: 999px;
    background: rgba(255,255,255,.18); color: #fff; font-size: .82rem;
}

/* ボタン・入力 */
.stButton > button[kind="primary"], .stDownloadButton > button, .stFormSubmitButton > button[kind="primary"] {
    border-radius: 14px; font-weight: 700; padding: .7rem 1rem;
}
.stButton > button[kind="primary"], .stFormSubmitButton > button[kind="primary"] {
    border: none; background: linear-gradient(135deg, #4f46e5, #7c3aed); color: #fff;
}
.stButton > button[kind="primary"]:hover {filter: brightness(1.08);}
.stTextInput input, .stTextArea textarea {border-radius: 12px;}

/* タブ */
.stTabs [data-baseweb="tab"] {font-weight: 700; padding: 8px 14px;}

/* セクション見出しチップ */
.sec-head {
    display: inline-block; padding: 6px 16px; border-radius: 999px; margin-bottom: 10px;
    font-weight: 800; font-size: 1.0rem; color: #fff;
}
.sec-0 {background: linear-gradient(135deg, #4f46e5, #7c3aed);}
.sec-1 {background: linear-gradient(135deg, #0ea5e9, #2563eb);}
.sec-2 {background: linear-gradient(135deg, #f59e0b, #ea580c);}
.sec-3 {background: linear-gradient(135deg, #ec4899, #db2777);}

.step {text-align: center; padding: 6px 4px;}
.step .ico {font-size: 1.8rem;}
.step .txt {font-size: .9rem; opacity: .8;}
</style>
""",
    unsafe_allow_html=True,
)

# ---------- ヒーロー（ログイン前でもタイトルが見える） ----------
st.markdown(
    f"""
<div class="hero">
  <div class="hero-title">🔗 {APP_NAME}</div>
  <div class="hero-sub">{APP_TAGLINE}　URLや学術PDFから、あなたの要望に沿って「要約・内容の索引・キーワード・ゼミ用コメントシート」をつくります。できたノートはPDFにでき、別のAIで検証もできます。</div>
  <span class="hero-chip">Claude ＆ Gemini 対応</span><span class="hero-chip">あなた自身のAPIキーで利用</span>
</div>
""",
    unsafe_allow_html=True,
)


# =====================================================================
#  設定の読み込み（secretsは、すべて「あれば使う」だけ。無くても動きます）
# =====================================================================
def get_secret(name: str) -> str:
    try:
        return st.secrets.get(name, "")
    except Exception:
        return ""


# =====================================================================
#  アカウント（ユーザー情報の保存）
#   ・パスワードは「ハッシュ」だけを保存（元の文字は保存しません）
#   ・APIキーは「あなたのパスワードで暗号化」して保存（管理者にも読めません）
# =====================================================================
PBKDF2_ROUNDS = 200_000
USERNAME_RE = re.compile(r"^[a-z0-9_.@-]{3,32}$")
PROVIDERS = ["Claude", "Gemini"]


def pbkdf2(password: str, salt_hex: str) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), bytes.fromhex(salt_hex), PBKDF2_ROUNDS, dklen=32)


def encrypt_keys(keys: dict, enc_raw: bytes) -> str:
    if Fernet is None:
        raise RuntimeError("cryptography ライブラリが入っていないため、キーを保存できません。")
    return Fernet(base64.urlsafe_b64encode(enc_raw)).encrypt(json.dumps(keys).encode("utf-8")).decode("utf-8")


def decrypt_keys(token: str, enc_raw: bytes) -> dict:
    if not token or Fernet is None:
        return {}
    try:
        data = Fernet(base64.urlsafe_b64encode(enc_raw)).decrypt(token.encode("utf-8"))
        return json.loads(data.decode("utf-8"))
    except (InvalidToken, ValueError):
        return {}


class SQLiteStore:
    """手軽な保存先（このサーバー内のファイル）。自分のPCや、ディスクが消えない環境向け。"""

    name = "SQLite"

    def __init__(self, path: str):
        self.path = path
        with closing(self._conn()) as c:
            c.execute(
                "CREATE TABLE IF NOT EXISTS users ("
                "username TEXT PRIMARY KEY, pw_salt TEXT, pw_hash TEXT, enc_salt TEXT, "
                "keys_enc TEXT DEFAULT '', created REAL)"
            )
            c.commit()

    def _conn(self):
        c = sqlite3.connect(self.path, timeout=10)
        c.row_factory = sqlite3.Row
        return c

    def get(self, username: str):
        with closing(self._conn()) as c:
            row = c.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
            return dict(row) if row else None

    def create(self, row: dict) -> bool:
        try:
            with closing(self._conn()) as c:
                c.execute(
                    "INSERT INTO users (username, pw_salt, pw_hash, enc_salt, keys_enc, created) VALUES (?,?,?,?,?,?)",
                    (row["username"], row["pw_salt"], row["pw_hash"], row["enc_salt"], row["keys_enc"], row["created"]),
                )
                c.commit()
            return True
        except sqlite3.IntegrityError:
            return False

    def update(self, username: str, **fields):
        cols = ", ".join(f"{k} = ?" for k in fields)
        with closing(self._conn()) as c:
            c.execute(f"UPDATE users SET {cols} WHERE username = ?", (*fields.values(), username))
            c.commit()

    def delete(self, username: str):
        with closing(self._conn()) as c:
            c.execute("DELETE FROM users WHERE username = ?", (username,))
            c.commit()


class SupabaseStore:
    """消えない保存先（Supabase／無料枠あり）。Secretsに SUPABASE_URL と SUPABASE_KEY を入れると使われます。"""

    name = "Supabase"

    def __init__(self, url: str, key: str):
        self.base = url.rstrip("/") + "/rest/v1/users"
        self.h = {"apikey": key, "Authorization": f"Bearer {key}", "Content-Type": "application/json"}

    def get(self, username: str):
        r = requests.get(self.base, headers=self.h, params={"username": f"eq.{username}", "select": "*"}, timeout=15)
        r.raise_for_status()
        rows = r.json()
        return rows[0] if rows else None

    def create(self, row: dict) -> bool:
        r = requests.post(self.base, headers={**self.h, "Prefer": "return=minimal"}, json=row, timeout=15)
        if r.status_code == 409:
            return False
        r.raise_for_status()
        return True

    def update(self, username: str, **fields):
        r = requests.patch(self.base, headers=self.h, params={"username": f"eq.{username}"}, json=fields, timeout=15)
        r.raise_for_status()

    def delete(self, username: str):
        r = requests.delete(self.base, headers=self.h, params={"username": f"eq.{username}"}, timeout=15)
        r.raise_for_status()


@st.cache_resource
def get_store():
    url, key = get_secret("SUPABASE_URL"), get_secret("SUPABASE_KEY")
    if url and key:
        return SupabaseStore(url, key)
    return SQLiteStore(get_secret("DB_PATH") or "manalink_users.db")


def start_session(username: str, password: str, row: dict):
    enc_raw = pbkdf2(password, row["enc_salt"])
    st.session_state["user"] = username
    st.session_state["enc_key"] = enc_raw
    st.session_state["saved_keys"] = decrypt_keys(row.get("keys_enc") or "", enc_raw)


def do_signup(username: str, password: str, password2: str, invite: str):
    username = username.strip().lower()
    required = get_secret("INVITE_CODE")
    if required and invite.strip() != required:
        return False, "招待コードが違います。"
    if not USERNAME_RE.match(username):
        return False, "ユーザー名は、半角の英数字と _ . @ - で、3〜32文字にしてください。"
    if len(password) < 8:
        return False, "パスワードは8文字以上にしてください。"
    if password != password2:
        return False, "パスワード（確認）が一致しません。"
    pw_salt, enc_salt = os.urandom(16).hex(), os.urandom(16).hex()
    row = {
        "username": username,
        "pw_salt": pw_salt,
        "pw_hash": pbkdf2(password, pw_salt).hex(),
        "enc_salt": enc_salt,
        "keys_enc": "",
        "created": time.time(),
    }
    try:
        ok = get_store().create(row)
    except Exception as e:
        return False, f"アカウントを保存できませんでした：{e}"
    if not ok:
        return False, "そのユーザー名は、すでに使われています。"
    start_session(username, password, row)
    return True, ""


def do_login(username: str, password: str):
    username = username.strip().lower()
    if st.session_state.get("fails", 0) >= 5:
        return False, "失敗が続いたため、ページを再読み込みしてから、もう一度お試しください。"
    try:
        row = get_store().get(username)
    except Exception as e:
        return False, f"アカウント情報を読み込めませんでした：{e}"
    ok = bool(row) and hmac.compare_digest(pbkdf2(password, row["pw_salt"]).hex(), row["pw_hash"])
    if not ok:
        st.session_state["fails"] = st.session_state.get("fails", 0) + 1
        time.sleep(1)
        return False, "ユーザー名かパスワードが違います。"
    st.session_state["fails"] = 0
    start_session(username, password, row)
    return True, ""


def persist_keys():
    """保存済みAPIキーを、暗号化してアカウントに書き込む"""
    token = encrypt_keys(st.session_state.get("saved_keys", {}), st.session_state["enc_key"])
    get_store().update(st.session_state["user"], keys_enc=token)


def require_login():
    if st.session_state.get("user"):
        return
    store = get_store()
    with st.container(border=True):
        tab_in, tab_up = st.tabs(["🔑 ログイン", "✨ アカウント作成"])
        with tab_in:
            with st.form("login_form"):
                u = st.text_input("ユーザー名")
                p = st.text_input("パスワード", type="password")
                go = st.form_submit_button("ログイン", type="primary", use_container_width=True)
            if go:
                ok, msg = do_login(u, p)
                if ok:
                    st.rerun()
                else:
                    st.error(msg)
        with tab_up:
            with st.form("signup_form"):
                u2 = st.text_input("ユーザー名（半角英数字と _ . @ - ／3〜32文字）")
                p2 = st.text_input("パスワード（8文字以上）", type="password")
                p3 = st.text_input("パスワード（確認）", type="password")
                inv = ""
                if get_secret("INVITE_CODE"):
                    inv = st.text_input("招待コード")
                go2 = st.form_submit_button("アカウントを作る", type="primary", use_container_width=True)
            if go2:
                ok, msg = do_signup(u2, p2, p3, inv)
                if ok:
                    st.rerun()
                else:
                    st.error(msg)
            st.caption("アカウントを作ったあと、あなた自身のAPIキー（ClaudeかGemini）を登録します。AIの利用料は、あなたのAPIアカウントにかかります。")
    with st.expander("🔒 しくみとプライバシー"):
        st.markdown(
            "- **パスワード**は、元の文字ではなく「ハッシュ」だけを保存します。\n"
            "- **APIキー**は、あなたのパスワードで暗号化して保存します。パスワードを忘れると、キーは復元できません（アカウントを作り直してください）。\n"
            "- 資料の本文や、AIの出力は、このアプリのサーバーには保存しません（この画面を閉じると消えます。必要なら、PDFなどで保存してください）。\n"
            "- 使うAPIキーは、AIの会社（Anthropic／Google）に送られます。ほかのサービスと同じパスワードは使わないでください。"
        )
        st.caption(
            f"アカウントの保存先：{store.name}"
            + ("（このアプリのサーバー内。無料の公開環境では、アプリの再起動で消えることがあります）" if store.name == "SQLite" else "")
        )
    st.stop()


require_login()

# =====================================================================
#  定数
# =====================================================================
SECTION_ICONS = ["📝", "🗂️", "🔑", "💬"]
PDF_DIRECT_MAX = 18 * 1024 * 1024  # PDFをAIに直接渡せる上限（約18MB）
PDF_NOTICE = "（添付のPDFが資料の全文です。図・表・数式・レイアウトも読み取って、内容に反映してください。）"

# モデル
CLAUDE_MODELS = {
    "claude-sonnet-5-5": "claude-sonnet-5-5（標準・おすすめ）",
    "claude-haiku-5-5": "claude-haiku-5-5（最速・軽め）",
    "claude-opus-5-5": "claude-opus-5-5（最も精密・遅め）",
}
GEMINI_MODELS = {
    "gemini-3.8-flash": "gemini-3.8-flash（標準・おすすめ）",
    "gemini-3.5-flash-lite": "gemini-3.5-flash-lite（最速・軽め）",
    "gemini-3.7-flash": "gemini-3.7-flash（予備）",
    "gemini-3.1-pro-preview": "gemini-3.1-pro-preview（精密・遅め）",
}
CLAUDE_PDF_MAX_PAGES = 100  # ClaudeがPDFを直接読める上限ページ数

# 「出力する前の要望」のテンプレート
REQUEST_TEMPLATES = {
    "（選ばずに自分で書く）": "",
    "初心者向けに": "専門知識がない人でもわかるように、やさしい言葉とたとえ話を使って説明してください。",
    "試験・テスト対策": "試験対策として、覚えるべき重要ポイントと、問われそうな点を中心に整理してください。",
    "発表の準備": "この内容を発表するために、全体の流れと、聞き手に伝えるべき要点を中心に整理してください。",
    "研究の方法・結果に注目": "研究の目的・方法（対象者・手続き）・結果・結論を中心に、数値も含めて整理してください。",
    "批判的に読む": "主張の強み・弱点、根拠が弱い点、追加で確認すべき点も指摘してください。",
}

# 追加で作る（出力後）用のテンプレート
EXTRA_TEMPLATES = {
    "（選ばずに自分で書く）": "",
    "発表原稿をつくる": "この内容を5分で発表するための原稿を、導入・本論・まとめの構成で作ってください。",
    "スライド構成案": "この内容を発表するスライドの構成案を、スライドごとのタイトルと要点で作ってください。",
    "用語集をつくる": "専門用語を10個ほど抜き出し、それぞれ初心者向けの一行解説をつけて用語集にしてください。",
    "批判的に検討する": "この内容の強み、弱点、根拠が弱い点、追加で確認すべき点を整理してください。",
    "次の研究アイデア": "この研究・主張を発展させるために、次にやるべき研究や調査のアイデアを5つ、理由つきで提案してください。",
}

QUICK_QUESTIONS = [
    "結論を一言でいうと？",
    "初心者向けにたとえ話で説明して",
    "この内容の弱点や限界は？",
    "出てくる用語をやさしく解説して",
]

# 検証（他のAIで評価する）の観点
EVAL_ASPECTS = [
    "正確性（数値・固有名詞・用語・因果関係が、資料と一致しているか）",
    "網羅性（資料の重要な点が、抜けていないか）",
    "妥当性（資料に書かれていない推測や、論理の飛躍が混ざっていないか）",
    "要約のバランス（字数・強調する点の偏りは適切か）",
    "作者への質問の質（本質を突いているか、答えが資料に書かれていないか）",
    "わかりやすさ・学習しやすさ（初学者が理解しやすい構成か）",
]

# 次の生成AI（プロンプトをコピーして、開く）
AI_SITES = [
    ("Gemini", "https://gemini.google.com/app", "#1a73e8"),
    ("ChatGPT", "https://chatgpt.com/", "#10a37f"),
    ("DeepSeek", "https://chat.deepseek.com/", "#4d6bfe"),
    ("Claude", "https://claude.ai/new", "#d97757"),
]

# =====================================================================
#  出力の「根底」にするプロンプト（ゼミのコメントシート）
#   → 学習ノート・追加作成・チャット・見直し・他AIでの検証、すべての土台になります
# =====================================================================
ZEMI_HEAD = """# 指示
あなたは大学の社会科学系ゼミ（政治学や教育学など）に参加する、非常に優秀で分析力のある学生です。
提供された研究発表のレジュメや資料を深く読み込み、ゼミでの議論を活発にするための「コメントシート」を作成してください。
指導教員や発表者に対する敬意を持ちつつ、論理的で自然な日本語（丁寧な「です・ます調」）で出力してください。"""

ZEMI_VIEWPOINTS = """# 評価の観点（以下の3項目を必ず含めること）
2-1. 研究の良いところ、面白いところ、優れている点は何か？（理論の適用や手法の工夫など、できるだけ具体的に）
2-2. 疑問に思ったこと、よく分からなかったことへの質問（変数の定義や因果関係の飛躍など）
2-3. 研究がより良くなるためには、具体的にどうしたら良いか？（分析手法や比較対象に関する建設的なアドバイス）"""

ZEMI_RULES = """# ⚠️ 厳守事項（出力フォーマットの制限）
以下のルールを完全に遵守して文章を生成してください。違反したフォーマットは無効とします。

1. 【AI特有のメタタグの禁止】
「なぜ聞きたいか：」「(疑問・アドバイス)」「[補足]」「(良い点)」といった、AI特有の機械的な見出しや、カッコ書きによるメタ説明は **一切使用しないでください**。

2. 【過剰な箇条書きの禁止】
細かすぎる階層の箇条書きは避け、人間が自然に書くような「段落（パラグラフ）」を基本とした文章構成にしてください。必要最低限のシンプルな箇条書き（・）のみ許可します。

3. 【自然な対話トーン】
ロボットのような無機質な分類ではなく、「〜という工夫が非常に面白いと感じました」「一方で、〇〇の定義について少し曖昧に感じたのですが〜」「〜してみてはいかがでしょうか」といった、ゼミの場にふさわしい、温かみのある学術的な対話トーンを維持してください。

4. 【根拠の明示】
一般的な感想ではなく、「資料の〇ページにある〜」「〇〇という変数について〜」など、入力資料の具体的な箇所を引用しながらコメントしてください。"""

# 学習ノート・検証の土台（指示＋評価の観点＋厳守事項）／追加作成・チャットの土台（指示＋厳守事項）
ZEMI_BASE_FULL = f"{ZEMI_HEAD}\n\n{ZEMI_VIEWPOINTS}\n\n{ZEMI_RULES}"
ZEMI_BASE_LIGHT = f"{ZEMI_HEAD}\n\n{ZEMI_RULES}"

PAGE_HINT = (
    "※資料に [p.数字] というページ番号の目印がある場合は、「資料の〇ページにある〜」のように、ページ番号を使って示してください。"
    "目印がない場合（Web記事など）は、節の見出しや、短い引用で、箇所を示してください。"
)

# 資料への忠実さ（カッコ書きのタグは使わず、文章の中で自然に区別させる）
GROUNDING_NORMAL = (
    "【資料への忠実さ】資料に書かれている内容に基づいて書いてください。"
    "資料にないことを推測で補う場合は、「資料には書かれていませんが、〜ではないかと考えます」のように、"
    "文章の中で自然に区別してください（カッコ書きのタグは使わないこと）。"
)
GROUNDING_STRICT = """【資料への忠実さ（厳守）】
・資料に書かれている事実と、あなたの推測は、必ず区別する。推測は「〜ではないかと考えます」のように、文章の中で自然に示す（カッコ書きのタグは使わない）。
・数値・固有名詞・専門用語は、資料のとおりに書く。勝手に言い換えたり、丸めたりしない。
・主な主張や数値には、わかる範囲でページ（p.数字）を添える。
・資料に書かれていないことは、「資料には書かれていません」と述べる。"""

# 学習ノート用プロンプト
NOTE_PROMPT = """{base}

# このツールでの出力形式
上の「指示」「評価の観点」「厳守事項」を土台にして、次の構成で、日本語で出力してください。
見出しの行（## と ### の行）は、下に書いたとおりに、そのまま使ってください。見出し以外の機械的なラベルは、書かないでください。

## 1-1. 要約
{summary_spec}

## 1-2. 内容の索引
文章の流れに沿って、扱われているトピックを順番に5〜10項目、「・トピック名（p.3）：何が書かれているかの一行説明」の形で並べる。本の目次のイメージで、階層は作らない。

## 1-3. キーワード・重要ポイント
「・用語や論点：一行の説明」の形で、3〜5個。

## 2. ゼミ用コメントシート
次の3つの小見出しを、この順で必ず入れ、それぞれ、段落（パラグラフ）で書いてください。
### 2-1. 研究の良いところ・面白いところ
### 2-2. 疑問に思ったこと・質問
### 2-3. より良くするためのアドバイス

# ユーザーの要望
{request}
※上の要望を最優先で反映してください。ただし、上の出力形式（見出し）と、厳守事項は、必ず守ってください。

{grounding}
{page_hint}

# 入力資料
{text}
"""

# PDF／HTML出力のデザイン
PRINT_CSS = """
body{font-family:"Meiryo","Yu Gothic","Hiragino Sans","Noto Sans CJK JP",sans-serif;line-height:1.85;color:#111;font-size:11pt;margin:0}
h1{font-size:20pt;border-bottom:3px solid #4f46e5;padding-bottom:6px;margin-top:0}
h2{font-size:14pt;color:#fff;background:#4f46e5;padding:4px 12px;border-radius:6px;margin-top:22px}
h3{font-size:12pt;color:#4f46e5;margin-bottom:4px}
blockquote{border-left:4px solid #c7d2fe;margin:8px 0;padding:4px 12px;background:#f5f6ff;color:#333}
table{border-collapse:collapse;margin:8px 0}td,th{border:1px solid #bbb;padding:4px 8px}
li{margin-bottom:4px}
hr{border:none;border-top:1px solid #ddd;margin:16px 0}
@page{size:A4;margin:16mm}
h1,h2,h3{page-break-after:avoid} li,blockquote{page-break-inside:avoid}
"""


# =====================================================================
#  関数
# =====================================================================
@st.cache_data(show_spinner=False, ttl=3600)
def fetch_article(target_url: str) -> str:
    """Jina Reader APIで本文を取得する"""
    res = requests.get(
        "https://r.jina.ai/" + target_url,
        headers={"Accept": "text/plain"},
        timeout=30,
    )
    res.raise_for_status()
    return res.text


def extract_title(text: str) -> str:
    m = re.search(r"^Title:\s*(.+)$", text, re.M)
    return m.group(1).strip() if m else "（タイトル不明）"


def extract_body(text: str) -> str:
    """Jinaの出力から、ヘッダー情報を除いた本文だけを取り出す"""
    marker = "Markdown Content:"
    if marker in text:
        return text.split(marker, 1)[1].strip()
    return text.strip()


@st.cache_data(show_spinner=False)
def extract_pdf(data: bytes, filename: str):
    """PDFからページ番号つきでテキストを取り出す。(タイトル, 本文) を返す"""
    reader = PdfReader(io.BytesIO(data))
    if reader.is_encrypted:
        reader.decrypt("")
    pages = []
    for i, page in enumerate(reader.pages, start=1):
        t = (page.extract_text() or "").strip()
        if t:
            pages.append(f"[p.{i}]\n{t}")
    meta_title = ""
    try:
        meta_title = (reader.metadata.title or "").strip() if reader.metadata else ""
    except Exception:
        pass
    if meta_title.lower() in ("untitled", "") or meta_title.lower().startswith("microsoft"):
        meta_title = ""
    title = meta_title or filename.rsplit(".", 1)[0]
    return title, "\n\n".join(pages)


def get_model(key: str, model: str):
    genai.configure(api_key=key)
    return genai.GenerativeModel(model)


@st.cache_data(show_spinner=False)
def count_pages(data: bytes) -> int:
    try:
        return len(PdfReader(io.BytesIO(data)).pages)
    except Exception:
        return 0


def pdf_direct_ok(data: bytes) -> bool:
    """PDFをAIにそのまま渡せるか（サイズ・ページ数の上限チェック）"""
    if len(data) > PDF_DIRECT_MAX:
        return False
    if provider == "Claude" and count_pages(data) > CLAUDE_PDF_MAX_PAGES:
        return False
    return True


def stream_text(key: str, model: str, prompt: str, pdf: bytes = None, max_tokens: int = 8000):
    """AIの回答を、できた部分から順に返す。pdfを渡すと、PDFそのものもAIに読ませる。
    （選ばれているAI＝Claude / Gemini に合わせて自動で切り替わります）"""
    if provider == "Claude":
        if anthropic is None:
            raise RuntimeError("anthropic ライブラリが入っていません。pip install anthropic を実行してください。")
        client = anthropic.Anthropic(api_key=key)
        if pdf:
            content = [
                {
                    "type": "document",
                    "source": {
                        "type": "base64",
                        "media_type": "application/pdf",
                        "data": base64.standard_b64encode(pdf).decode("utf-8"),
                    },
                },
                {"type": "text", "text": prompt},
            ]
        else:
            content = prompt
        with client.messages.stream(
            model=model,
            max_tokens=max_tokens,
            messages=[{"role": "user", "content": content}],
        ) as stream:
            for piece in stream.text_stream:
                if piece:
                    yield piece
    else:
        contents = [{"mime_type": "application/pdf", "data": pdf}, prompt] if pdf else prompt
        response = get_model(key, model).generate_content(contents, stream=True)
        for chunk in response:
            try:
                piece = chunk.text
            except Exception:
                piece = ""
            if piece:
                yield piece


def ocr_pdf(key: str, model: str, data: bytes) -> str:
    """文字を読み取れないPDF（スキャン画像など）を、AIに画像として読ませて書き起こす"""
    prompt = (
        "このPDFの本文を、省略せずにテキストへ書き起こしてください。"
        "各ページの先頭に [p.1]、[p.2] のようにページ番号の目印を付けてください。"
        "図や表は、内容を短い文で説明してください。"
    )
    return "".join(stream_text(key, model, prompt, pdf=data, max_tokens=32000))


def generate_live(caption: str, key: str, model: str, prompt: str, pdf: bytes = None, max_tokens: int = 8000) -> str:
    """生成の途中経過を、枠の中にリアルタイム表示して、結果（全文）を返す"""
    live = st.empty()
    out = ""
    try:
        with live.container(border=True):
            st.caption(caption)
            box = st.empty()
            for piece in stream_text(key, model, prompt, pdf, max_tokens):
                out += piece
                box.markdown(out)
    finally:
        live.empty()
    return out


def build_summary_spec(n: int) -> str:
    """要約の字数（自由）から、AIへの指示文をつくる"""
    if n <= 150:
        return f"約{n}字（±15%を目安）で、1つの段落に簡潔にまとめる"
    if n <= 600:
        paras, flow = "2〜3段落", "背景・主張・結論の流れがわかるように"
    elif n <= 1500:
        paras = "3〜5段落"
        flow = "（論文・発表資料なら）背景・目的・方法・結果・結論、（記事なら）主張・根拠・結論の流れがわかるように"
    else:
        paras = "5〜8段落"
        flow = "（論文・発表資料なら）背景・目的・方法・結果・考察・結論、（記事なら）主張・根拠・反論・結論の流れがわかるように"
    return f"最初に「一言でいうと：」で始まる1文を書き、そのあと、{flow}、全体で約{n}字（±15%を目安に守る）、{paras}に分けて書く"


def build_note_prompt(text: str, summary_spec: str, request: str, strict: bool) -> str:
    return NOTE_PROMPT.format(
        base=ZEMI_BASE_FULL,
        text=text,
        summary_spec=summary_spec,
        request=request.strip() or "（特になし。標準の形式でまとめてください）",
        grounding=GROUNDING_STRICT if strict else GROUNDING_NORMAL,
        page_hint=PAGE_HINT,
    )


def build_verify_prompt(text: str, draft: str) -> str:
    return f"""{ZEMI_BASE_LIGHT}

# あなたの役割
あなたは、上の指示にもとづいて書かれた「下書き」を、校閲する担当です。【資料】と【下書き】を照らし合わせ、誤りを直した最終版を出力してください。
・資料と合っていない内容、資料に根拠のない記述、数値・固有名詞・用語の誤りを直す。
・直す必要がない部分は、そのまま残す。
・見出し（## 1-1. 要約／## 1-2. 内容の索引／## 1-3. キーワード・重要ポイント／## 2. ゼミ用コメントシート／### 2-1／### 2-2／### 2-3）と、文体（です・ます調の段落）は、下書きと同じにする。
・厳守事項に反する表現（機械的なラベル、カッコ書きのメタ説明など）が残っていたら、自然な文章に直す。
・最終版の内容だけを出力する（修正点の説明は書かない）。

# 資料
{text}

# 下書き
{draft}
"""


def build_custom_prompt(text: str, instruction: str, strict: bool) -> str:
    return f"""{ZEMI_BASE_LIGHT}

# 今回の依頼
上の指示と厳守事項を土台にして、次の依頼に、日本語で答えてください。

{instruction}

{GROUNDING_STRICT if strict else GROUNDING_NORMAL}
{PAGE_HINT}

# 入力資料
{text}
"""


def build_chat_prompt(text: str, chat: list, strict: bool) -> str:
    history = "\n".join(
        ("ユーザー" if m["role"] == "user" else "AI") + "：" + m["content"] for m in chat[:-1]
    )
    return f"""{ZEMI_BASE_LIGHT}

# 今回の依頼
上の指示と厳守事項を土台にして、ユーザーの質問に、日本語でわかりやすく答えてください。
チャットなので、まず質問に直接答え、長くなりすぎないようにしてください。

{GROUNDING_STRICT if strict else GROUNDING_NORMAL}
{PAGE_HINT}

# 入力資料
{text}

# これまでの会話
{history or "（なし）"}

# 新しい質問
{chat[-1]["content"]}
"""


def build_eval_prompt(note: dict, include_source: bool, include_output: bool, aspects: list, extra: str) -> str:
    """別の生成AIに、「このツールのAIの出力」を評価させるためのプロンプト（出力はHTML・人間が読みやすい文章）"""
    m = note.get("meta", {})
    ctx = []
    if m.get("provider"):
        ctx.append(f"・使ったAI：{m['provider']}（{m.get('model', '')}）")
    if m.get("summary_chars"):
        ctx.append(f"・要約の指定字数：約{m['summary_chars']}字")
    ctx.append(f"・精度優先モード：{'オン（PDFを直接読み取り、見直しあり）' if m.get('accuracy') else 'オフ'}")
    if note.get("request"):
        ctx.append(f"・ユーザーがAIに伝えた要望：{note['request']}")
    if m.get("body_chars") and m.get("read_chars") and m["read_chars"] < m["body_chars"]:
        ctx.append(
            f"・注意：資料の全文は{m['body_chars']:,}文字ですが、ツールのAIには先頭{m['read_chars']:,}文字だけを渡しました。"
            "それより後ろの内容の抜けは、ツールの設定による制限として、AIの読み取りの問題とは分けて扱ってください。"
        )
    if note.get("pdf"):
        ctx.append("・ツールのAIには、PDFそのもの（図・表を含む）を直接渡しました。")
    ctx_text = "\n".join(ctx)

    src = note["body"].strip() if include_source else "（資料の原文は、ここに貼り付けるか、PDF・ファイルとして添付してください）"
    out = note["result"].strip() if include_output else "（このツールのAIの出力は、ここに貼り付けるか、PDF・ファイルとして添付してください）"
    asp = "\n".join(f"・{a}" for a in (aspects or EVAL_ASPECTS))
    extra_block = f"\n特に見てほしいこと：{extra.strip()}\n" if extra.strip() else ""

    return f"""{ZEMI_HEAD}
ここでは、ある生成AIが資料Aを読んで作った「学習ノート（コメントシート）B」が、資料Aを正しく読み取れているか、内容が妥当かを検討し、ゼミで共有する講評として書いてください。
添付ファイルがある場合は、そのファイルも読んでください（AとBを、ファイルで渡している場合があります）。

# 検討する対象
A：元の資料（研究発表のレジュメなど）
B：このツールのAIが作った学習ノート（PDFにしたものと同じ内容）

# ツールの設定
{ctx_text}

# 検討のしかた
・Bの主張を1つずつ確かめ、Aの該当箇所と照らし合わせてください。結果は、「資料の〇ページでは〜とあり、Bの〜という記述と一致しています」のように、文章の中で書いてください。
・Aに書かれていない知識で、「正しい」と判断しないでください。判断の根拠は、Aとの一致だけにしてください。
・Aそのものに誤りや疑問点があれば、2-2の中で、「資料そのものについて」と断ったうえで触れてください。
・断定しすぎず、人間が最終判断できるように、根拠と、判断が分かれる点を示してください。
特に重視する観点：
{asp}
{extra_block}
# 評価の観点（Bに対して、以下の3項目を必ず含めること）
2-1. Bの良いところ、優れている点は何か？（資料を正確に読み取れている箇所、要点を的確に押さえている箇所など、できるだけ具体的に）
2-2. Bについて疑問に思ったこと、確認したいこと（資料と食い違う数値・用語、根拠の弱い断定、因果関係の飛躍、資料にない内容の混入など）
2-3. Bがより良くなるためには、具体的にどうしたら良いか？（抜けている重要点の補い方、言い換えるべき表現、原典で確認すべき箇所など）

{ZEMI_RULES}

# 出力形式（HTML）
人間が読みやすいように、次の構成の「1つのHTMLファイル」で出力してください。
・「1. 総合所見」：Bは資料を正確に反映しているか、内容は妥当か。結論を、2〜3文の段落で。
・「2-1.」「2-2.」「2-3.」：上の評価の観点に、それぞれ段落で答える。
・「3. 人間が考えるための問い」：読み手が、自分で考えを深められる問いを、2〜3個、文章で。
・「4. 原典で確認してほしい箇所」：シンプルな「・」の箇条書きのみ。
・文章が中心です。表、★、バッジ、絵文字、色分けのラベル（✅など）は使わないでください。
・デザインは、落ち着いた配色で、余白と行間をゆったり取る。本文の幅は700px程度。フォントは "Hiragino Sans","Yu Gothic","Meiryo",sans-serif。印刷しても読めるようにする。
・<!DOCTYPE html> から </html> までの完全なHTMLにする。CSSは <style> に埋め込み、外部の画像・フォント・スクリプトは使わない。
・返答は、HTMLのみ。前置きや後書きは書かない。HTMLをそのまま表示できる機能（Canvas・アーティファクトなど）があれば、それを使う。無ければ、コードブロック1つで出力する。

# 入力資料
━━━━━━━━ A：資料（原文）ここから ━━━━━━━━
{src}
━━━━━━━━ A：ここまで ━━━━━━━━

━━━━━━━━ B：このツールのAIの出力 ここから ━━━━━━━━
{out}
━━━━━━━━ B：ここまで ━━━━━━━━
"""


def split_sections(result: str):
    """'## 見出し' ごとに (見出し, 本文) へ分ける。失敗したら空リスト"""
    parts = [p for p in re.split(r"(?m)^##(?!#)\s*", result) if p.strip()]
    sections = []
    for p in parts:
        head, _, text = p.partition("\n")
        sections.append((head.strip(), text.strip()))
    return sections if len(sections) >= 2 else []


def render_summary(text: str):
    """要約：先頭の「一言でいうと」を目立たせて表示する"""
    first, _, rest = text.partition("\n\n")
    if first.replace("*", "").strip().startswith("一言でいうと"):
        st.info(first.replace("**", ""))
        if rest.strip():
            st.markdown(rest)
    else:
        st.markdown(text)


def build_export(note: dict) -> str:
    m = note.get("meta", {})
    out = f"# {note['title']}\n\n{note['url']}\n\n"
    info = []
    if m.get("provider"):
        info.append(f"AI：{m['provider']}（{m.get('model', '')}）")
    if m.get("summary_chars"):
        info.append(f"要約：約{m['summary_chars']}字")
    info.append("精度優先：" + ("オン" if m.get("accuracy") else "オフ"))
    if m.get("read_chars"):
        info.append(f"AIが読んだ文字数：{m['read_chars']:,}／本文全体：{m.get('body_chars', 0):,}")
    info.append("作成日：" + datetime.date.today().isoformat())
    out += "> " + "　／　".join(info) + "\n\n"
    if note.get("request"):
        out += f"> 要望：{note['request']}\n\n"
    out += note["result"]
    if st.session_state.get("my_answer"):
        out += f"\n\n## ✍️ 自分のメモ\n\n{st.session_state['my_answer']}"
    runs = st.session_state.get("prompt_runs", [])
    if runs:
        out += "\n\n## ➕ 追加で作ったもの\n\n"
        out += "\n\n---\n\n".join(f"**プロンプト：** {r['prompt']}\n\n{r['output']}" for r in runs)
    chat = st.session_state.get("chat", [])
    if chat:
        out += "\n\n## 🤖 AIとの質疑\n\n" + "\n\n".join(
            ("**Q:** " if m_["role"] == "user" else "**A:** ") + m_["content"] for m_ in chat
        )
    return out


def md_to_html(md_text: str) -> str:
    """Markdown → HTML。AIの出力に混ざったHTMLタグは、無効にする（安全のため）"""
    safe = md_text.replace("&", "&amp;").replace("<", "&lt;")
    if md_lib is None:
        return "<pre style='white-space:pre-wrap'>" + safe + "</pre>"
    return md_lib.markdown(safe, extensions=["extra", "sane_lists"])


def build_html_doc(title: str, body_html: str) -> str:
    return (
        '<!doctype html><html lang="ja"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        f"<title>{html.escape(title)}</title><style>{PRINT_CSS}.wrap{{max-width:820px;margin:0 auto;padding:24px}}</style>"
        f'</head><body><div class="wrap">{body_html}</div></body></html>'
    )


def print_button(body_html: str):
    """押すと、ブラウザの印刷画面が開く（送信先を「PDFに保存」にすると、PDFになる）"""
    components.html(
        f"""
<style>{PRINT_CSS}
#doc{{display:none}}
.pbtn{{width:100%;padding:12px;border:none;border-radius:14px;font-weight:700;font-size:15px;color:#fff;
cursor:pointer;background:linear-gradient(135deg,#4f46e5,#7c3aed);font-family:inherit}}
@media print{{.pbtn{{display:none}}#doc{{display:block}}}}
</style>
<button class="pbtn" onclick="window.print()">📄 PDFにする（印刷画面で「PDFに保存」）</button>
<div id="doc">{body_html}</div>
""",
        height=62,
    )


def ai_jump_buttons(prompt: str):
    """押すと、プロンプトをコピーして、次の生成AIのページを新しいタブで開く"""
    js_prompt = json.dumps(prompt).replace("</", "<\\/")
    btns = "".join(
        f'<button class="b" style="background:{color}" data-url="{url}">{name}へ</button>' for name, url, color in AI_SITES
    )
    components.html(
        f"""
<style>
.row{{display:flex;gap:8px;flex-wrap:wrap}}
.b{{flex:1;min-width:110px;padding:12px 8px;border:none;border-radius:12px;color:#fff;font-weight:700;
font-size:15px;cursor:pointer;font-family:inherit}}
.b:hover{{filter:brightness(1.1)}}
#msg{{margin-top:8px;font-size:13px;font-family:inherit;color:#555}}
</style>
<div class="row">{btns}</div>
<div id="msg">ボタンを押すと、プロンプトがコピーされ、AIのページが開きます。開いたら貼り付け（Ctrl+V）して送信してください。</div>
<script>
const text = {js_prompt};
function copyText() {{
  const ta = document.createElement("textarea");
  ta.value = text;
  document.body.appendChild(ta);
  ta.select();
  let ok = false;
  try {{ ok = document.execCommand("copy"); }} catch (e) {{}}
  document.body.removeChild(ta);
  if (!ok && navigator.clipboard) {{ navigator.clipboard.writeText(text); ok = true; }}
  return ok;
}}
document.querySelectorAll(".b").forEach(b => {{
  b.onclick = () => {{
    const ok = copyText();
    const w = window.open(b.dataset.url, "_blank");
    document.getElementById("msg").textContent = ok
      ? (w ? "✅ コピーしました。開いたページに貼り付け（Ctrl+V）して送信してください。"
           : "✅ コピーしました。ページが開かないときは、下のリンクから開いてください。")
      : "⚠️ 自動コピーに失敗しました。下の欄の文章を、手動でコピーしてください。";
  }};
}});
</script>
""",
        height=110,
    )


def apply_request_template():
    t = REQUEST_TEMPLATES.get(st.session_state.get("req_tpl"), "")
    if t:
        st.session_state["request"] = t


def apply_extra_template():
    t = EXTRA_TEMPLATES.get(st.session_state.get("extra_tpl"), "")
    if t:
        st.session_state["user_prompt"] = t


def source_for_ai(note: dict, max_chars: int) -> str:
    """AIに渡す資料の本体（PDFを直接渡している場合は、その旨の一文）"""
    return PDF_NOTICE if note.get("pdf") else note["body"][:max_chars]


def key_block(label: str, value: str, uid: str):
    """保管しているAPIキーを、伏せ字で表示し、ボタンでコピーできるようにする"""
    masked = value[:4] + "•" * 12 + value[-4:] if len(value) > 8 else "•" * 8
    show = st.toggle("キーを表示", value=False, key=f"show_{uid}")
    st.text(value if show else masked)
    components.html(
        f"""
        <button id="copy" style="width:100%;padding:8px;border:1px solid #ccc;
            border-radius:10px;background:#fff;cursor:pointer;font-size:14px;">
            📋 クリックでコピー
        </button>
        <script>
        const key = {json.dumps(value)};
        const btn = document.getElementById("copy");
        btn.onclick = () => {{
            const ta = document.createElement("textarea");
            ta.value = key;
            document.body.appendChild(ta);
            ta.select();
            let ok = false;
            try {{ ok = document.execCommand("copy"); }} catch (e) {{}}
            document.body.removeChild(ta);
            if (!ok && navigator.clipboard) {{ navigator.clipboard.writeText(key); }}
            btn.textContent = "✅ コピーしました";
            setTimeout(() => btn.textContent = "📋 クリックでコピー", 1500);
        }};
        </script>
        """,
        height=48,
    )


def save_typed_keys():
    """入力したAPIキーを、暗号化して、アカウントに保存する（ボタンのコールバック）"""
    saved = dict(st.session_state.get("saved_keys", {}))
    added = []
    for prov in PROVIDERS:
        typed = st.session_state.get(f"typed_{prov}", "").strip()
        if typed:
            saved[prov] = typed
            st.session_state[f"typed_{prov}"] = ""
            added.append(prov)
    if not added:
        st.session_state["key_msg"] = ("warning", "保存するキーを、入力欄に入れてください。")
        return
    st.session_state["saved_keys"] = saved
    try:
        persist_keys()
        st.session_state["key_msg"] = ("success", f"{'・'.join(added)} のキーを、暗号化して保存しました。")
    except Exception as e:
        st.session_state["key_msg"] = ("error", f"保存に失敗しました（この画面の間は使えます）：{e}")


def delete_saved_key(prov: str):
    saved = dict(st.session_state.get("saved_keys", {}))
    saved.pop(prov, None)
    st.session_state["saved_keys"] = saved
    try:
        persist_keys()
        st.session_state["key_msg"] = ("success", f"{prov} のキーを削除しました。")
    except Exception as e:
        st.session_state["key_msg"] = ("error", f"削除に失敗しました：{e}")


# =====================================================================
#  サイドバー（アカウント・マイAPIキー・AIチャット）
# =====================================================================
saved_keys = st.session_state.get("saved_keys", {})

with st.sidebar:
    st.markdown(f"### 🔗 {APP_NAME}")
    st.caption(f"👤 {st.session_state['user']} でログイン中")

    with st.expander("🔐 マイAPIキー", expanded=not any(saved_keys.values())):
        st.caption("あなた自身のAPIキーを使います。使った分の料金は、あなたのAPIアカウントにかかります。パスワードで暗号化して保存されます。")
        for prov, how in [
            ("Claude", "キーの取得：Claude Console（console.anthropic.com）。事前にクレジットの購入が必要です。"),
            ("Gemini", "キーの取得：Google AI Studio（aistudio.google.com/apikey）。"),
        ]:
            st.markdown(f"**{prov}**")
            if saved_keys.get(prov):
                st.caption("✅ 保存済み")
                key_block(prov, saved_keys[prov], prov.lower())
                st.button("🗑️ このキーを削除", key=f"del_{prov}", on_click=delete_saved_key, args=(prov,), use_container_width=True)
            st.text_input(f"{prov} APIキーを入力", type="password", key=f"typed_{prov}", placeholder="ここに貼り付け")
            st.caption(how)
        st.button("💾 入力したキーを保存（暗号化）", on_click=save_typed_keys, type="primary", use_container_width=True)
        st.caption("保存しなくても、入力したキーは、この画面の間は使えます。")
        if st.session_state.get("key_msg"):
            kind, msg = st.session_state.pop("key_msg")
            getattr(st, kind)(msg)

    chat_slot = st.container()  # ← AIチャットは、あとでここに描く
    st.divider()
    if st.button("🔒 ログアウト", use_container_width=True):
        st.session_state.clear()
        st.rerun()
    with st.expander("⚠️ アカウントを削除"):
        st.caption("アカウントと、保存したAPIキーが、完全に消えます。")
        sure = st.checkbox("本当に削除する")
        if st.button("アカウントを削除する", disabled=not sure):
            try:
                get_store().delete(st.session_state["user"])
                st.session_state.clear()
                st.rerun()
            except Exception as e:
                st.error(f"削除できませんでした：{e}")

# =====================================================================
#  入力エリア
# =====================================================================
key_notice = st.container()  # ← APIキーが無いときの案内を、あとで入れる

with st.container(border=True):
    mode = st.radio(
        "入力方法", ["🔗 URL", "📄 PDFファイル"], horizontal=True, label_visibility="collapsed"
    )
    url = ""
    pdf_file = None
    if mode == "🔗 URL":
        url = st.text_input("🔗 記事のURL", placeholder="https://example.com/article")
    else:
        pdf_file = st.file_uploader("📄 学術論文・発表資料などのPDF", type=["pdf"])
        st.caption("文字を読み取れないPDF（スキャン画像など）は、AIが画像として読み取ります。")

    st.markdown("**💭 AIへの要望（出力する前に、読み方を伝えられます）**")
    st.selectbox(
        "テンプレート",
        list(REQUEST_TEMPLATES),
        key="req_tpl",
        on_change=apply_request_template,
        label_visibility="collapsed",
    )
    st.text_area(
        "要望",
        key="request",
        height=95,
        label_visibility="collapsed",
        placeholder="例：心理学の卒業研究のために読んでいます。研究の方法とサンプルの人数を中心に整理してください。（空欄でもOK）",
    )

    c_len, c_acc = st.columns([3, 2])
    with c_len:
        summary_chars = st.slider(
            "📏 要約の字数",
            min_value=100,
            max_value=3000,
            value=500,
            step=50,
            help="好きな字数に変えられます。目安の字数で、AIが書きます（多少のずれはあります）。",
        )
    with c_acc:
        accuracy = st.toggle(
            "🎯 精度優先モード",
            value=False,
            help="PDFをAIに直接読ませ、正確さのルールを厳しくし、最後に本文と照らして見直します。精度は上がりますが、時間は2倍近くかかります。大事な論文向け。",
        )
        if accuracy:
            st.caption("PDF直接読み取り＋見直し。時間はかかります。")

    request_text = st.session_state.get("request", "")
    with st.expander("🧾 AIに送るプロンプトを確認する"):
        st.caption("あなたの要望から、AIへの指示文が自動で組み立てられます。内容を確かめたいときに開いてください。")
        st.text_area(
            "プロンプト（読み取り専用）",
            value=build_note_prompt("（ここに本文が入ります）", build_summary_spec(summary_chars), request_text, accuracy),
            height=280,
            disabled=True,
        )

    run = st.button("✨ 学習ノートをつくる", type="primary", use_container_width=True)

with st.expander("⚙️ 詳細設定（AIの種類・モデル・読ませる文字数）"):
    provider = st.radio(
        "🧠 使うAI",
        PROVIDERS,
        index=1 if (saved_keys.get("Gemini") and not saved_keys.get("Claude")) else 0,
        horizontal=True,
        key="provider",
        help="Claude（Anthropic）かGemini（Google）を切り替えられます。どちらも、そのAIのAPIキーが必要です。",
    )
    models = CLAUDE_MODELS if provider == "Claude" else GEMINI_MODELS
    model_name = st.selectbox(
        "使用するモデル",
        list(models),
        format_func=lambda m: models[m],
        key=f"model_{provider}",
        help=(
            "速くしたいときは claude-haiku-5-5、精度優先モードでは claude-opus-5-5 がおすすめです。"
            if provider == "Claude"
            else "速くしたいときは gemini-3.5-flash-lite、精度優先モードでは gemini-3.1-pro-preview がおすすめです。"
        ),
    )
    read_all = st.toggle("全文を読ませる（上限なし）", value=False, help="長い資料も、最後まで読ませます。時間と料金は増えます。")
    read_limit = st.slider(
        "⚡ AIに読ませる文字数の上限",
        min_value=10_000,
        max_value=1_000_000,
        value=120_000,
        step=10_000,
        disabled=read_all,
        help="範囲が広いほど、資料の後ろまで読めます。少ないほど、速く・安くなります。",
    )

typed_key = st.session_state.get(f"typed_{provider}", "").strip()
use_key = typed_key or saved_keys.get(provider, "")
max_chars = 10**9 if read_all else read_limit

if not use_key:
    with key_notice:
        st.info(
            f"🔐 はじめに：左のサイドバー「マイAPIキー」に、あなたの **{provider}** のAPIキーを入れてください。"
            "（使った分の料金は、あなたのAPIアカウントにかかります）"
        )

# =====================================================================
#  実行処理
# =====================================================================
if run:
    if not use_key:
        st.warning(f"左のサイドバー「マイAPIキー」に、{provider} のAPIキーを入れてください。")
        st.stop()

    article = ""
    pdf_bytes = None
    if mode == "🔗 URL":
        if not url.strip():
            st.warning("URLを入力してください。")
            st.stop()
        if not url.strip().startswith(("http://", "https://")):
            st.warning("URLは http:// または https:// から始めてください。")
            st.stop()
        try:
            with st.spinner("📡 本文を取得中..."):
                article = fetch_article(url.strip())
        except requests.exceptions.RequestException as e:
            st.error(f"本文の取得に失敗しました: {e}")
            st.stop()
        title = extract_title(article)
        body = extract_body(article)
        source = url.strip()
    else:
        if pdf_file is None:
            st.warning("PDFファイルを選んでください。")
            st.stop()
        pdf_bytes = pdf_file.getvalue()
        can_direct = pdf_direct_ok(pdf_bytes)
        try:
            with st.spinner("📄 PDFから本文を取り出し中..."):
                title, body = extract_pdf(pdf_bytes, pdf_file.name)
            if len(body.strip()) < 300:
                if accuracy and can_direct:
                    body = body.strip() or "（文字データのないPDFです。AIがPDFを直接読み取りました。）"
                else:
                    with st.spinner("🖼️ 文字データが少ないため、AIが画像として読み取り中...（時間がかかります）"):
                        body = ocr_pdf(use_key, model_name, pdf_bytes)
        except Exception as e:
            st.error(f"PDFの読み取りに失敗しました: {e}")
            st.stop()
        article = body
        source = pdf_file.name

    if not body.strip():
        st.error("本文を取得できませんでした。別のURL・ファイルをお試しください。")
        st.stop()

    # 精度優先モード：PDFをAIに直接読ませる
    pdf_for_ai = None
    if accuracy and pdf_bytes:
        if pdf_direct_ok(pdf_bytes):
            pdf_for_ai = pdf_bytes
        else:
            st.warning("PDFが大きい（18MB超、またはClaudeで100ページ超）ため、文字を取り出す方式で読みます。")

    text_for_ai = PDF_NOTICE if pdf_for_ai else body[:max_chars]
    prompt = build_note_prompt(text_for_ai, build_summary_spec(summary_chars), request_text, accuracy)
    out_tokens = min(32000, 6000 + summary_chars * 3)  # 長い要約でも、途中で切れないように

    cache_src = f"{provider}|{model_name}|{accuracy}|{prompt}"
    if pdf_for_ai:
        cache_src += hashlib.md5(pdf_for_ai).hexdigest()
    cache_key = hashlib.md5(cache_src.encode("utf-8")).hexdigest()
    gen_cache = st.session_state.setdefault("gen_cache", {})

    if cache_key in gen_cache:
        result = gen_cache[cache_key]  # 同じ内容・設定なら、前回の結果をすぐ表示
    else:
        try:
            result = generate_live(
                "✍️ AIが書いています…（できた部分から順に表示されます）", use_key, model_name, prompt, pdf_for_ai, out_tokens
            )
        except Exception as e:
            st.error(f"AI処理に失敗しました（APIキーやモデル名を確認してください）: {e}")
            st.stop()
        if not result.strip():
            st.error("AIから応答がありませんでした。モデルを変えて、もう一度お試しください。")
            st.stop()

        # 精度優先モード：本文と照らして見直す
        if accuracy:
            try:
                checked = generate_live(
                    "🔍 本文と照らして、間違いがないか見直しています…",
                    use_key,
                    model_name,
                    build_verify_prompt(text_for_ai, result),
                    pdf_for_ai,
                    out_tokens,
                )
                if len(checked.strip()) >= len(result.strip()) * 0.5 and split_sections(checked):
                    result = checked
            except Exception as e:
                st.warning(f"見直しに失敗したため、下書きをそのまま表示します: {e}")
        gen_cache[cache_key] = result

    # 結果を保存（ボタンを押しても消えないように）
    st.session_state["note"] = {
        "url": source,
        "title": title,
        "article": article,
        "body": body,
        "result": result,
        "request": request_text.strip(),
        "pdf": pdf_for_ai,
        "accuracy": accuracy,
        "meta": {
            "provider": provider,
            "model": model_name,
            "summary_chars": summary_chars,
            "accuracy": accuracy,
            "body_chars": len(body),
            "read_chars": min(len(body), max_chars),
        },
    }
    st.session_state["my_answer"] = ""
    st.session_state["chat"] = []
    st.session_state["prompt_runs"] = []

# =====================================================================
#  結果表示
# =====================================================================
note = st.session_state.get("note")

if not note:
    c1, c2, c3, c4 = st.columns(4)
    for col, ico, txt in [
        (c1, "🔗", "①URLかPDFを入れる"),
        (c2, "💭", "②要望を伝える"),
        (c3, "✨", "③ボタンを押す"),
        (c4, "📄", "④PDF保存・検証"),
    ]:
        col.markdown(f'<div class="step"><div class="ico">{ico}</div><div class="txt">{txt}</div></div>', unsafe_allow_html=True)
else:
    st.markdown(f"#### 📰 {note['title']}")
    m1, m2, m3 = st.columns(3)
    m1.metric("本文の文字数", f"{len(note['body']):,}")
    m2.metric("AIに渡した文字数", "PDFそのもの" if note.get("pdf") else f"{min(len(note['body']), max_chars):,}")
    m3.metric("モード", "🎯 精度優先" if note.get("accuracy") else "⚡ 通常")
    st.caption(note["url"])
    if note.get("request"):
        st.info(f"💭 あなたの要望：{note['request']}")

    tab_ai, tab_extra, tab_eval, tab_raw = st.tabs(["📚 学習ノート", "➕ 追加で作る", "🔍 他のAIで検証", "📄 本文"])

    # ===== 学習ノート =====
    with tab_ai:
        sections = split_sections(note["result"])
        if sections:
            for i, (head, text) in enumerate(sections):
                icon = SECTION_ICONS[i] if i < len(SECTION_ICONS) else "•"
                with st.container(border=True):
                    st.markdown(
                        f'<div class="sec-head sec-{min(i, 3)}">{icon} {html.escape(head)}</div>',
                        unsafe_allow_html=True,
                    )
                    if i == 0:
                        render_summary(text)
                    else:
                        st.markdown(text)
                    if i == len(sections) - 1:
                        st.text_area(
                            "✍️ 自分のメモ（相手の答えを想像してみよう）",
                            key="my_answer",
                            height=120,
                            placeholder="ここに気づきや、自分なりの答えをメモできます",
                        )
        else:
            st.markdown(note["result"])

        # ---- 書き出し（PDF／HTML／Markdown）----
        export_md = build_export(note)
        export_html_body = md_to_html(export_md)
        st.markdown("**📤 書き出し**")
        print_button(export_html_body)
        st.caption("↑ 押すと印刷画面が開きます。送信先（プリンター）を「PDFに保存」にすると、PDFになります。")
        d1, d2 = st.columns(2)
        d1.download_button(
            "🌐 HTMLで保存",
            data=build_html_doc(note["title"], export_html_body),
            file_name="manalink_note.html",
            mime="text/html",
            use_container_width=True,
        )
        d2.download_button(
            "💾 Markdownで保存",
            data=export_md,
            file_name="manalink_note.md",
            mime="text/markdown",
            use_container_width=True,
        )

    # ===== 追加で作る（出力後に、別のプロンプトで作る） =====
    with tab_extra:
        st.caption("学習ノートとは別に、自分の指示（プロンプト）で、この資料から何でも作れます。")
        st.selectbox(
            "📋 テンプレートから選ぶ（任意）",
            list(EXTRA_TEMPLATES),
            key="extra_tpl",
            on_change=apply_extra_template,
        )
        st.text_area(
            "✏️ あなたのプロンプト",
            key="user_prompt",
            height=130,
            placeholder="例：この研究の新規性を、高校生にもわかるように説明してください。",
        )
        go = st.button("🚀 このプロンプトで作る", type="primary", use_container_width=True, key="go_prompt")

        just_ran = False
        if go:
            instruction = st.session_state.get("user_prompt", "").strip()
            if not instruction:
                st.warning("プロンプトを入力してください。")
            elif not use_key:
                st.warning("APIキーを、サイドバーの「マイAPIキー」に入れてください。")
            else:
                prompt = build_custom_prompt(source_for_ai(note, max_chars), instruction, bool(note.get("accuracy")))
                with st.container(border=True):
                    st.markdown(
                        f'<div class="sec-head sec-0">🧩 {html.escape(instruction[:40])}</div>',
                        unsafe_allow_html=True,
                    )
                    try:
                        out = st.write_stream(stream_text(use_key, model_name, prompt, note.get("pdf"), 16000))
                        runs = st.session_state.get("prompt_runs", [])
                        runs.insert(0, {"prompt": instruction, "output": out})
                        st.session_state["prompt_runs"] = runs
                        just_ran = True
                    except Exception as e:
                        st.error(f"作成に失敗しました: {e}")

        runs = st.session_state.get("prompt_runs", [])
        for r in (runs[1:] if just_ran else runs):
            with st.container(border=True):
                st.markdown(f'<div class="sec-head sec-0">🧩 {html.escape(r["prompt"][:40])}</div>', unsafe_allow_html=True)
                st.markdown(r["output"])
        if runs and st.button("🗑️ 結果をクリア", key="clear_prompt"):
            st.session_state["prompt_runs"] = []
            st.rerun()

    # ===== 他のAIで検証 =====
    with tab_eval:
        st.markdown("このツールのAIが作ったノートが、**正確で妥当か**を、別のAIにも評価してもらいます。")
        st.markdown(
            "1. 下のボタンを押す → プロンプトがコピーされ、AIの画面が開きます\n"
            "2. 貼り付け（Ctrl+V）して送信（資料や、PDFにしたノートを**添付**すると、さらに確実）\n"
            "3. 出力された **HTML** を、画面で見るか、保存して開く"
        )
        e1, e2 = st.columns(2)
        inc_src = e1.toggle(
            "資料（原文）をプロンプトに貼り付ける",
            value=len(note["body"]) <= 50000,
            help="長い資料は、貼り付けずに、ファイルで添付するほうが安定します。",
        )
        inc_out = e2.toggle("このツールの出力を貼り付ける", value=True)
        aspects = st.multiselect("評価の観点", EVAL_ASPECTS, default=EVAL_ASPECTS[:4])
        extra_eval = st.text_input("特に見てほしいこと（任意）", placeholder="例：数値と、研究方法の説明が合っているかを重点的に")

        eval_prompt = build_eval_prompt(note, inc_src, inc_out, aspects, extra_eval)
        final_prompt = st.text_area("評価用プロンプト（自由に編集できます）", value=eval_prompt, height=280)
        st.caption(f"文字数：{len(final_prompt):,}字　｜　長すぎるときは「資料（原文）を貼り付ける」をオフにして、ファイルで添付してください。")

        st.markdown("**➡️ 次の生成AIへ**")
        ai_jump_buttons(final_prompt)
        lc = st.columns(len(AI_SITES))
        for col, (name, url_, _) in zip(lc, AI_SITES):
            col.link_button(f"{name}を開く", url_, use_container_width=True)
        st.caption("↑ 自動で開かないとき用のリンクです（その場合は、先にプロンプトをコピーしてください）。")
        st.download_button(
            "📥 プロンプトを保存（.txt）",
            data=final_prompt,
            file_name="manalink_eval_prompt.txt",
            mime="text/plain",
            use_container_width=True,
        )
        st.info("💡 PDFにしたノートは、「📚 学習ノート」タブの「PDFにする」から作れます。評価するAIに、そのPDFを添付してもOKです。")

    # ===== 本文 =====
    with tab_raw:
        body_text = note["body"]
        if len(body_text) > max_chars and not note.get("pdf"):
            st.info(f"本文が長いため、AIには先頭{max_chars:,}文字のみ渡しています。")
        as_raw = st.toggle("記号のまま表示（コピー用）", value=False)
        if as_raw:
            st.text_area("本文", body_text, height=500)
        else:
            with st.container(height=500, border=True):
                st.markdown(body_text)
        st.download_button(
            "💾 本文を保存（.txt）",
            data=f"{note['title']}\n{note['url']}\n\n{body_text}",
            file_name="manalink_body.txt",
            mime="text/plain",
            use_container_width=True,
        )

# =====================================================================
#  サイドバーのAIチャット（最後に描く＝最新のノートを使える）
# =====================================================================
with chat_slot:
    st.markdown("#### 🤖 AIに質問")
    if not note:
        st.info("学習ノートをつくると、ここで、その資料についてAIに質問できます。")
    else:
        st.caption(f"📰 {note['title'][:40]}")
        chat = st.session_state.get("chat", [])
        history_box = st.container(height=380)  # 会話はここに表示（スクロールできます）

        with st.expander("💡 質問の例", expanded=not chat):
            quick = None
            for idx, label in enumerate(QUICK_QUESTIONS):
                if st.button(label, key=f"quick_{idx}", use_container_width=True):
                    quick = label

        with st.form("ask_form", clear_on_submit=True):
            q = st.text_area("質問を入力", height=80, placeholder="この資料について質問してください")
            ask = st.form_submit_button("📨 送信", use_container_width=True)

        question = quick or (q.strip() if ask else "")
        if question and not use_key:
            st.warning("APIキーが必要です。")
            question = ""
        if question:
            chat.append({"role": "user", "content": question})

        with history_box:
            if not chat:
                st.caption("まだ会話はありません。下の入力欄から質問してみましょう。")
            for m in chat:
                with st.chat_message(m["role"]):
                    st.markdown(m["content"])
            if question:
                with st.chat_message("assistant"):
                    try:
                        prompt = build_chat_prompt(source_for_ai(note, max_chars), chat, bool(note.get("accuracy")))
                        answer = st.write_stream(stream_text(use_key, model_name, prompt, note.get("pdf")))
                        chat.append({"role": "assistant", "content": answer})
                    except Exception as e:
                        chat.pop()  # 失敗した質問は履歴から外す
                        st.error(f"回答に失敗しました: {e}")
        st.session_state["chat"] = chat

        if chat and st.button("🗑️ 会話をリセット", key="reset_chat", use_container_width=True):
            st.session_state["chat"] = []
            st.rerun()
