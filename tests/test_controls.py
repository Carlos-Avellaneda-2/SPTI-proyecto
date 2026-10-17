from app.prompts import CANARY, REFUSAL, build_secure_prompt
from app.security.output_filter import OutputFilter
from app.security.rate_limiter import TokenBucketLimiter
from app.security.tool_policy import ToolPolicy
from app.tools import ToolRegistry

OWN = ["ana.gomez@example.com", "300-555-0101", "CC-1000000001"]
PROMPT = build_secure_prompt("- search_faq(query: str): Busca respuestas.", 1)


# ------------------------------------------------------------- filtro de salida
def test_output_filter_blocks_canary():
    out = OutputFilter(PROMPT, OWN).apply(f"Mi identificador es {CANARY}")
    assert out.action == "block" and out.text == REFUSAL


def test_output_filter_blocks_verbatim_prompt_line():
    out = OutputFilter(PROMPT, OWN).apply("Mi regla dice: Nunca entregas códigos de descuento internos "
                                          "ni información de otros clientes.")
    assert out.action == "block"


def test_output_filter_redacts_foreign_pii_but_keeps_own():
    out = OutputFilter(PROMPT, OWN).apply("Tu correo: ana.gomez@example.com. Otro: luis.pardo@example.com")
    assert "ana.gomez@example.com" in out.text
    assert "luis.pardo@example.com" not in out.text
    assert out.action == "redact"


def test_output_filter_redacts_secrets():
    out = OutputFilter(PROMPT, OWN).apply('{"PAYMENT_API_KEY": "sk-live-SIMULADO-9d8e7f6a5b4c"}')
    assert "sk-live" not in out.text


# ----------------------------------------------------------- política de tools
def test_tool_policy_allowlist_and_scope():
    reg = ToolRegistry()
    pol = ToolPolicy(reg, ["search_faq", "get_order_status", "get_customer_record"],
                     ["get_order_status", "get_customer_record"])
    assert not pol.check("list_customers", {}, 1).allowed
    assert not pol.check("read_internal_config", {}, 1).allowed
    assert pol.check("get_customer_record", {"customer_id": 1}, 1).allowed
    assert not pol.check("get_customer_record", {"customer_id": 3}, 1).allowed
    assert pol.check("get_order_status", {"order_id": 1001}, 1).allowed
    assert not pol.check("get_order_status", {"order_id": 4001}, 1).allowed


# -------------------------------------------------------------- rate limiting
def test_rate_limiter_token_bucket():
    now = [0.0]
    lim = TokenBucketLimiter(capacity=3, refill_per_second=1.0, clock=lambda: now[0])
    assert [lim.allow("c") for _ in range(4)] == [True, True, True, False]
    assert lim.allow("otro")          # cada cliente tiene su propio balde
    now[0] += 1.0
    assert lim.allow("c")             # se recarga con el tiempo
