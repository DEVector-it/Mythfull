import base64
import html
import io
import logging
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

from flask import Flask, jsonify, render_template, request
from flask_cors import CORS

try:
    from PIL import Image, ImageDraw, ImageFont  # type: ignore

    PIL_AVAILABLE = True
    PIL_IMPORT_ERROR: Optional[Exception] = None
except Exception as exc:  # pragma: no cover - executed when Pillow missing
    Image = ImageDraw = ImageFont = None  # type: ignore
    PIL_AVAILABLE = False
    PIL_IMPORT_ERROR = exc


logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

if not PIL_AVAILABLE and PIL_IMPORT_ERROR:
    logging.warning(
        "Pillow is unavailable (%s). Falling back to SVG image rendering.",
        PIL_IMPORT_ERROR,
    )

APP_NAME = "Study Buddy AI"
BETA_LABEL = "Study Buddy AI Beta"
COPYRIGHT_NOTICE = "Study Buddy AI © {}. All rights reserved.".format(datetime.utcnow().year)
STUDY_BUDDY_API_KEY = "AIzaSyDe9DZANR3BiUFX-w1Ol7Rnkh_GHU8k-5w"
API_KEY_HEADER = "X-StudyBuddy-Key"
PUBLISHING_SUGGESTIONS = [
    {
        "name": "Render",
        "headline": "Deploy directly from GitHub with autoscaling for Python web apps.",
        "url": "https://render.com/",
        "notes": "Supports background workers for queued tutoring sessions and cron jobs for nightly study summaries."
    },
    {
        "name": "Vercel",
        "headline": "Great for front-end heavy experiences with serverless APIs.",
        "url": "https://vercel.com/",
        "notes": "Pair with a managed database (Supabase/Planetscale) for transcript storage."
    },
    {
        "name": "Azure App Service",
        "headline": "Enterprise ready hosting with regional redundancy and compliance tooling.",
        "url": "https://azure.microsoft.com/en-us/products/app-service/",
        "notes": "Use managed identity for secure Gemini or OpenAI key rotation."
    }
]


@dataclass
class Capability:
    """Describes an individual skill that a plan can unlock."""

    id: str
    label: str
    description: str
    category: str


@dataclass
class Plan:
    slug: str
    title: str
    subtitle: str
    price: str
    includes: List[str]
    myth_full_focus: str
    upgrades: List[str]
    recommended: bool = False
    beta: bool = True
    extra: Dict[str, str] = field(default_factory=dict)

    def serialize(self) -> Dict[str, object]:
        return {
            "slug": self.slug,
            "title": self.title,
            "subtitle": self.subtitle,
            "price": self.price,
            "includes": self.includes,
            "myth_full_focus": self.myth_full_focus,
            "upgrades": self.upgrades,
            "recommended": self.recommended,
            "beta": self.beta,
            "extra": self.extra,
        }


@dataclass
class Persona:
    """Represents a themed Study Buddy teaching persona."""

    key: str
    tone: str
    focus: str
    specialties: List[str]


CAPABILITIES: Dict[str, Capability] = {
    "guided-reflection": Capability(
        id="guided-reflection",
        label="Guided Reflection",
        description="Structured prompts that train students how to evaluate their learning strategies using Myth Full heuristics.",
        category="mentorship",
    ),
    "mythic-expansion": Capability(
        id="mythic-expansion",
        label="Mythic Expansion",
        description="Adaptive answer elaboration that mimics the depth you expect from GPT-style systems.",
        category="explanations",
    ),
    "exam-sim": Capability(
        id="exam-sim",
        label="Exam Simulator",
        description="Time-boxed quizzes that adjust difficulty and instantly surface targeted review cards.",
        category="assessment",
    ),
    "image-lab": Capability(
        id="image-lab",
        label="Image Lab",
        description="Generates visual study aids, diagrams, and cover art for project submissions.",
        category="creativity",
    ),
}

PLANS: Dict[str, Plan] = {
    "myth-max": Plan(
        slug="myth-max",
        title="Myth Max",
        subtitle="Starter access to Myth Full mentoring with responsive tutoring.",
        price="$29 / month",
        includes=[
            "Live Study Buddy chat tuned for student productivity",
            "Myth Full guided-reflection prompts",
            "Foundational creative image cards",
        ],
        myth_full_focus="Foundation",
        upgrades=[CAPABILITIES["guided-reflection"].label, CAPABILITIES["mythic-expansion"].label],
        recommended=False,
        extra={"tag": "Launch Ready"},
    ),
    "goat-myth": Plan(
        slug="goat-myth",
        title="GOAT Myth",
        subtitle="Serious students unlock richer context and peer coaching rooms.",
        price="$79 / month",
        includes=[
            "Priority Study Buddy responses with deeper GPT-style reasoning",
            "Unlimited collaboration rooms with Myth Full note sync",
            "Access to beta exam simulations",
        ],
        myth_full_focus="Momentum",
        upgrades=[
            CAPABILITIES["guided-reflection"].label,
            CAPABILITIES["mythic-expansion"].label,
            CAPABILITIES["exam-sim"].label,
        ],
        recommended=True,
        extra={"tag": "Most Popular"},
    ),
    "myth-full-legend": Plan(
        slug="myth-full-legend",
        title="Legendary Myth Full",
        subtitle="All-access experience with dedicated cohort strategy and tailored visuals.",
        price="$200 / month",
        includes=[
            "Dedicated strategist with weekend office hours",
            "Unlimited image lab credits for visual memory hooks",
            "Curriculum alignment with your school or district",
        ],
        myth_full_focus="Mastery",
        upgrades=[
            CAPABILITIES["guided-reflection"].label,
            CAPABILITIES["mythic-expansion"].label,
            CAPABILITIES["exam-sim"].label,
            CAPABILITIES["image-lab"].label,
        ],
        recommended=False,
        extra={"tag": "Myth Full Elite"},
    ),
}

PERSONAS = [
    Persona(
        key="mentor",
        tone="Warm and encouraging with academically rigorous feedback.",
        focus="Helps students convert notes into mastery checkpoints.",
        specialties=["Study planning", "Concept explanations", "Mindset coaching"],
    ),
    Persona(
        key="strategist",
        tone="Data-driven with milestone tracking and accountability loops.",
        focus="Pairs Myth Full heuristics with modern learning science.",
        specialties=["Habit forming", "Exam simulation", "Progress analytics"],
    ),
    Persona(
        key="creator",
        tone="Visual-first and creativity fueled.",
        focus="Transforms prompts into posters, flashcards, and presentations.",
        specialties=["Visual mnemonics", "Project ideation", "Image lab curation"],
    ),
]


class ExperienceEngine:
    """Coordinates plan capabilities, chat memory, and lightweight caching."""

    def __init__(self, plans: Dict[str, Plan]):
        self._plans = plans
        self._transcripts: Dict[str, List[Dict[str, str]]] = {}
        self._last_image_prompts: Dict[str, str] = {}

    def _validate_plan(self, slug: Optional[str]) -> Plan:
        if not slug or slug not in self._plans:
            logging.warning("Unknown plan '%s'. Falling back to myth-max.", slug)
            return self._plans["myth-max"]
        return self._plans[slug]

    def register_visit(self, slug: Optional[str]) -> Plan:
        plan = self._validate_plan(slug)
        transcript = self._transcripts.setdefault(plan.slug, [])
        transcript.append({
            "role": "system",
            "message": f"{APP_NAME} welcome ping captured at {datetime.utcnow().isoformat()}"
        })
        logging.debug("Registered visit for %s; transcript length now %s", plan.slug, len(transcript))
        return plan

    def chat(self, slug: Optional[str], message: str) -> Dict[str, object]:
        plan = self._validate_plan(slug)
        transcript = self._transcripts.setdefault(plan.slug, [])
        transcript.append({"role": "student", "message": message})

        myth_boost = ", ".join(plan.upgrades)
        response_text = (
            f"[{plan.title}] {APP_NAME} hears you! Based on our Myth Full {plan.myth_full_focus} stack, "
            f"here's a quick boost: {message.strip()} → Focus on evidence, elaborate with {myth_boost}. "
            "Remember, better responses are unlocked because your plan mirrors GPT-style depth and study heuristics."
        )

        transcript.append({"role": "assistant", "message": response_text})
        return {
            "plan": plan.serialize(),
            "persona": PERSONAS[len(transcript) % len(PERSONAS)].__dict__,
            "response": response_text,
            "transcript_length": len(transcript),
            "timestamp": datetime.utcnow().isoformat(),
        }

    def build_image(self, slug: Optional[str], prompt: str) -> Dict[str, str]:
        plan = self._validate_plan(slug)
        self._last_image_prompts[plan.slug] = prompt
        image_data = render_prompt_image(prompt, plan.title)
        return {
            "plan": plan.serialize(),
            "prompt": prompt,
            "image": image_data,
            "timestamp": datetime.utcnow().isoformat(),
        }

    def export_state(self) -> Dict[str, object]:
        return {
            "plans": [plan.serialize() for plan in self._plans.values()],
            "transcripts": self._transcripts,
            "last_image_prompts": self._last_image_prompts,
        }


def render_prompt_image(prompt: str, plan_title: str) -> str:
    """Create a study card encoded as a data URI."""
    if PIL_AVAILABLE and Image and ImageDraw and ImageFont:
        width, height = 512, 320
        background = (44, 62, 80)
        accent = (46, 204, 113)

        image = Image.new("RGB", (width, height), color=background)
        draw = ImageDraw.Draw(image)
        font_title = ImageFont.load_default()
        font_body = ImageFont.load_default()

        draw.rectangle([(0, 0), (width, 48)], fill=(26, 188, 156))
        draw.text((16, 12), f"{plan_title} Image Lab", fill=(255, 255, 255), font=font_title)

        wrapped = wrap_text(prompt, 60)
        draw.text((16, 72), wrapped, fill=accent, font=font_body)

        footer = "Powered by Myth Full creativity"
        draw.text((16, height - 28), footer, fill=(236, 240, 241), font=font_body)

        buffer = io.BytesIO()
        image.save(buffer, format="PNG")
        encoded = base64.b64encode(buffer.getvalue()).decode("utf-8")
        return f"data:image/png;base64,{encoded}"

    logging.debug("Using SVG fallback for prompt image rendering.")
    prompt_text = html.escape(prompt or "Study inspiration incoming!")
    title_text = html.escape(plan_title)
    svg = f"""
    <svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 512 320'>
        <defs>
            <linearGradient id='bg' x1='0%' y1='0%' x2='100%' y2='100%'>
                <stop offset='0%' stop-color='#1f2937'/>
                <stop offset='100%' stop-color='#0f172a'/>
            </linearGradient>
        </defs>
        <rect width='512' height='320' fill='url(#bg)' rx='24'/>
        <rect width='512' height='60' fill='#0ea5e9' rx='24'/>
        <text x='24' y='38' font-size='24' font-family='Inter, Arial, sans-serif' fill='#f8fafc'>
            {title_text} Image Lab
        </text>
        <foreignObject x='24' y='80' width='464' height='200'>
            <body xmlns='http://www.w3.org/1999/xhtml'>
                <div style='font-family:Inter,Arial,sans-serif;font-size:18px;color:#22d3ee;line-height:1.4;'>
                    {prompt_text}
                </div>
            </body>
        </foreignObject>
        <text x='24' y='300' font-size='16' font-family='Inter, Arial, sans-serif' fill='#e2e8f0'>
            Myth Full creativity placeholder
        </text>
    </svg>
    """
    encoded_svg = base64.b64encode(svg.encode("utf-8")).decode("utf-8")
    return f"data:image/svg+xml;base64,{encoded_svg}"


def wrap_text(text: str, line_length: int) -> str:
    words = text.split()
    lines: List[str] = []
    current: List[str] = []
    for word in words:
        current.append(word)
        if len(" ".join(current)) > line_length:
            lines.append(" ".join(current[:-1]))
            current = current[-1:]
    if current:
        lines.append(" ".join(current))
    if not lines:
        lines.append(text)
    return "\n".join(lines)


def ensure_index_placeholder():
    path = Path("index.html")
    if not path.exists():
        path.write_text("<html><body><h1>Study Buddy AI</h1></body></html>")


def build_app() -> Flask:
    ensure_index_placeholder()
    flask_app = Flask(__name__, template_folder=".")
    CORS(flask_app)
    engine = ExperienceEngine(PLANS)

    def validate_api_key(data: Optional[Dict[str, object]] = None) -> bool:
        candidate = request.headers.get(API_KEY_HEADER)
        if not candidate and data:
            candidate = str(data.get("api_key", ""))
        if not candidate:
            candidate = request.args.get("api_key")
        if candidate != STUDY_BUDDY_API_KEY:
            logging.warning("Rejected request with invalid API key: %s", candidate)
            return False
        return True

    @flask_app.route("/")
    def home() -> str:
        payload = {
            "app_name": APP_NAME,
            "beta_label": BETA_LABEL,
            "copyright": COPYRIGHT_NOTICE,
            "api_key": STUDY_BUDDY_API_KEY,
            "api_key_header": API_KEY_HEADER,
            "plans": [plan.serialize() for plan in PLANS.values()],
            "capabilities": [cap.__dict__ for cap in CAPABILITIES.values()],
            "personas": [persona.__dict__ for persona in PERSONAS],
            "publishing": PUBLISHING_SUGGESTIONS,
        }
        engine.register_visit(request.args.get("plan"))
        return render_template("index.html", payload=payload)

    @flask_app.get("/api/plans")
    def get_plans():
        return jsonify({
            "app": APP_NAME,
            "beta": BETA_LABEL,
            "plans": [plan.serialize() for plan in PLANS.values()],
            "capabilities": [cap.__dict__ for cap in CAPABILITIES.values()],
        })

    @flask_app.post("/api/chat")
    def chat():
        data = request.get_json(force=True)
        if not validate_api_key(data):
            return jsonify({
                "error": "Invalid or missing API key.",
                "status": "unauthorized",
            }), 401
        message = data.get("message", "Let's build a better study habit.")
        plan = data.get("plan")
        result = engine.chat(plan, message)
        return jsonify(result)

    @flask_app.post("/api/image")
    def create_image():
        data = request.get_json(force=True)
        if not validate_api_key(data):
            return jsonify({
                "error": "Invalid or missing API key.",
                "status": "unauthorized",
            }), 401
        prompt = data.get("prompt", "Design a mythic study booster card.")
        plan = data.get("plan")
        result = engine.build_image(plan, prompt)
        return jsonify(result)

    @flask_app.get("/api/state")
    def export_state():
        return jsonify(engine.export_state())

    @flask_app.get("/api/publishing")
    def publishing():
        return jsonify({
            "app": APP_NAME,
            "suggestions": PUBLISHING_SUGGESTIONS,
            "notes": "These platforms pair well with Study Buddy AI's Render-ready configuration.",
        })

    @flask_app.get("/api/status")
    def status():
        """Render health check endpoint."""
        return jsonify({
            "app": APP_NAME,
            "status": "ok",
            "timestamp": datetime.utcnow().isoformat(),
        })

    @flask_app.get("/api/config")
    def config():
        return jsonify({
            "app": APP_NAME,
            "api_key": STUDY_BUDDY_API_KEY,
            "api_key_header": API_KEY_HEADER,
        })

    return flask_app


app = build_app()


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
