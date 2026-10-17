"""Capa 4 (Secure): control de acceso a herramientas (allowlist + mínimo privilegio).

- Solo se pueden ejecutar herramientas de la allowlist.
- Las herramientas "con alcance de sesión" solo operan sobre recursos del
  cliente autenticado (su propio registro, sus propios pedidos).
"""
from __future__ import annotations

from dataclasses import dataclass

from app.tools import ToolRegistry


@dataclass
class ToolDecision:
    allowed: bool
    reason: str = ""


class ToolPolicy:
    def __init__(self, registry: ToolRegistry, allowlist: list[str], scoped_to_session: list[str]):
        self.registry = registry
        self.allowlist = set(allowlist)
        self.scoped = set(scoped_to_session)

    def check(self, name: str, args: dict, session_customer_id: int) -> ToolDecision:
        if name not in self.allowlist:
            return ToolDecision(False, f"herramienta_no_permitida:{name}")
        if name in self.scoped:
            if name == "get_customer_record":
                try:
                    target = int(args.get("customer_id"))
                except (TypeError, ValueError):
                    return ToolDecision(False, "argumento_invalido")
                if target != session_customer_id:
                    return ToolDecision(False, f"fuera_de_alcance:cliente_{target}")
            if name == "get_order_status":
                owner = self.registry.order_owner(args.get("order_id"))
                if owner is not None and owner != session_customer_id:
                    return ToolDecision(False, f"fuera_de_alcance:pedido_{args.get('order_id')}")
        return ToolDecision(True)
