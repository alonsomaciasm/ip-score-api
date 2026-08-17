#!/usr/bin/env python3
"""
Model Context Protocol (MCP) Server for IP Reputation Score API.
Exposes structured tools for AI Agents (Claude Desktop, Antigravity IDE, Cursor, LangChain)
to evaluate IP risk scores, check threat signals, and perform batch analyses.

Protocol: JSON-RPC 2.0 via Standard Input / Output (stdio)
"""

import sys
import json
import asyncio
import os

# Add project root directory to PYTHONPATH
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from app.config import settings
from app.security.logging import setup_logging
from app.feeds.updater import load_feeds_from_disk_fallback
from app.services.lookup import lookup_service
from app.services.overrides import overrides_store
from app.services.scoring import ScoringEngine
from app.models.request import ScoreRequest, BatchScoreRequest


TOOLS = [
    {
        "name": "evaluate_ip_risk",
        "description": "Evaluates the risk score (0-100), risk level (low, medium, high, critical), recommendation (allow, flag, challenge, block), threat signals (Tor, VPN, Proxy, Botnet C2, Abuse lists, Cloud Datacenter, Apple Private Relay, CDN egress), FCrDNS, ASN and network type for a given IPv4 or IPv6 address.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "ip": {
                    "type": "string",
                    "description": "The IPv4 or IPv6 address to evaluate for threat risk."
                },
                "allow_private": {
                    "type": "boolean",
                    "description": "Optional: set to true to allow private/local RFC 1918 IPs for testing.",
                    "default": False
                }
            },
            "required": ["ip"]
        }
    },
    {
        "name": "evaluate_batch_ip_risks",
        "description": "Evaluates threat risk scores for a list/batch of IPv4 or IPv6 addresses (up to 50 IPs) in a single call.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "ips": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "List of IPv4 or IPv6 addresses to evaluate."
                },
                "allow_private": {
                    "type": "boolean",
                    "description": "Optional: set to true to allow private/local RFC 1918 IPs for testing.",
                    "default": False
                }
            },
            "required": ["ips"]
        }
    },
    {
        "name": "get_ip_score_metrics_summary",
        "description": "Returns a summary of the IP Reputation Score system metrics, loaded threat feed capacities, scoring rules, and risk thresholds.",
        "inputSchema": {
            "type": "object",
            "properties": {}
        }
    }
]


def init_engine():
    """Initializes in-memory threat feeds and lookup services offline-first."""
    setup_logging(debug=False)
    load_feeds_from_disk_fallback()
    overrides_store.load_overrides()
    lookup_service.initialize()


async def handle_tool_call(name: str, arguments: dict):
    if name == "evaluate_ip_risk":
        ip_str = arguments.get("ip")
        allow_priv = arguments.get("allow_private", False)
        try:
            req = ScoreRequest(ip=ip_str, allow_private=allow_priv)
            resp = await ScoringEngine.calculate_score(req)
            return resp.model_dump()
        except Exception as e:
            return {"error": f"Invalid IP scoring request: {str(e)}"}

    elif name == "evaluate_batch_ip_risks":
        ips_list = arguments.get("ips", [])
        allow_priv = arguments.get("allow_private", False)
        try:
            req = BatchScoreRequest(ips=ips_list, allow_private=allow_priv)
            results = []
            for ip in req.ips:
                item_req = ScoreRequest(ip=ip, allow_private=allow_priv)
                res = await ScoringEngine.calculate_score(item_req)
                results.append({"ip": ip, "result": res.model_dump()})
            return {"total_evaluated": len(results), "results": results}
        except Exception as e:
            return {"error": f"Invalid batch IP scoring request: {str(e)}"}

    elif name == "get_ip_score_metrics_summary":
        from app.feeds.updater import feed_store
        return {
            "service": settings.PROJECT_NAME,
            "version": settings.VERSION,
            "environment": settings.ENVIRONMENT,
            "pii_zero_enabled": True,
            "threat_feeds_loaded": {
                "tor_exit_nodes": len(feed_store.tor_exits.iter_cidrs()),
                "botnet_c2_servers": len(feed_store.botnet_c2_ips.iter_cidrs()),
                "bogon_subnets": len(feed_store.bogon_ips.iter_cidrs()),
                "open_phishing_ips": len(feed_store.phishing_ips.iter_cidrs()),
                "abuse_listed_ips": len(feed_store.abuse_ips.iter_cidrs()),
                "apple_private_relays": len(feed_store.apple_relay_ips.iter_cidrs()),
                "cdn_egress_ips": len(feed_store.cdn_ips.iter_cidrs())
            },
            "risk_score_thresholds": {
                "0-29": "low (allow)",
                "30-59": "medium (flag/rate_limit)",
                "60-84": "high (challenge/captcha)",
                "85-100": "critical (block)"
            }
        }

    else:
        raise ValueError(f"Unknown tool: {name}")


async def main():
    init_engine()

    # Read JSON-RPC from stdio line-by-line
    while True:
        line = await asyncio.to_thread(sys.stdin.readline)
        if not line:
            break
        
        line_str = line.strip()
        if not line_str:
            continue

        try:
            req = json.loads(line_str)
        except json.JSONDecodeError:
            continue

        req_id = req.get("id")
        method = req.get("method")
        params = req.get("params", {})

        if method == "initialize":
            response = {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {"tools": {}},
                    "serverInfo": {
                        "name": "ip-score-api-mcp",
                        "version": settings.VERSION
                    }
                }
            }
            sys.stdout.write(json.dumps(response) + "\n")
            sys.stdout.flush()

        elif method == "notifications/initialized":
            pass

        elif method == "tools/list":
            response = {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {"tools": TOOLS}
            }
            sys.stdout.write(json.dumps(response) + "\n")
            sys.stdout.flush()

        elif method == "tools/call":
            tool_name = params.get("name")
            tool_args = params.get("arguments", {})
            try:
                result_data = await handle_tool_call(tool_name, tool_args)
                response = {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "content": [
                            {
                                "type": "text",
                                "text": json.dumps(result_data, indent=2, ensure_ascii=False)
                            }
                        ]
                    }
                }
            except Exception as e:
                response = {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {
                        "code": -32603,
                        "message": str(e)
                    }
                }
            sys.stdout.write(json.dumps(response) + "\n")
            sys.stdout.flush()

        else:
            if req_id is not None:
                response = {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {
                        "code": -32601,
                        "message": f"Method not found: {method}"
                    }
                }
                sys.stdout.write(json.dumps(response) + "\n")
                sys.stdout.flush()


if __name__ == "__main__":
    asyncio.run(main())
