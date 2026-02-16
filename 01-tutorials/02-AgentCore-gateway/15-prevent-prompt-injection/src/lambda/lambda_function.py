"""
SQL Injection Prevention Interceptor for Gateway MCP REQUESTS

This Lambda function intercepts Gateway MCP tools/call REQUESTS and analyzes
TOOL ARGUMENTS (not user prompts) for SQL injection attacks before allowing 
requests to reach database tools. It is configured as a REQUEST interceptor.

IMPORTANT: This protects at the TOOL LEVEL, not the agent level.
- Agent-level: Bedrock Guardrails protects the agent from prompt injection
- Tool-level: This interceptor protects database tools from SQL injection

The agent has already processed the user prompt by the time it calls a tool.
This interceptor analyzes the tool's query arguments to prevent SQL injection
before any database query executes.

DETECTION APPROACH:
This is a DEMO using heuristic pattern matching to detect common SQL injection
patterns. In production, the recommended deterministic control is to:
1. Disallow raw SQL in tool arguments
2. Require structured query templates or query builders
3. Use parameterized execution at the database layer

This heuristic detector identifies high-signal SQL injection indicators:
- Statement stacking (;) followed by SQL keywords
- Comment tokens (--, /*, */)
- UNION + SELECT combinations
- Tautologies (OR 1=1, AND 1=1)
- Time-based injection (SLEEP, WAITFOR DELAY, BENCHMARK)

Security: Fails CLOSED - blocks requests if SQL injection patterns are detected.
"""

import json
import re
import hashlib
from typing import Any, Dict, Tuple, List

# Configuration
STRICT_MODE = False  # If True, deny any raw SQL fields; if False, run heuristics
MAX_STRING_LENGTH = 10000  # Reject extremely long strings to avoid regex worst cases

# High-signal SQL Injection Detection Patterns
# These patterns focus on clear SQL injection indicators with low false positive rates
SQL_INJECTION_PATTERNS = [
    # Statement stacking - semicolon followed by SQL keywords
    (r';[\s\n]*\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|TRUNCATE|EXEC|EXECUTE)\b', 'STACKED_QUERY'),
    
    # SQL Comments - clear injection indicators
    (r'--', 'SQL_COMMENT_DASH'),
    (r'/\*', 'SQL_COMMENT_OPEN'),
    (r'\*/', 'SQL_COMMENT_CLOSE'),
    
    # UNION-based injection
    (r'\bUNION\b[\s\n]+\bSELECT\b', 'UNION_SELECT'),
    (r'\bUNION\b[\s\n]+\bALL\b[\s\n]+\bSELECT\b', 'UNION_ALL_SELECT'),
    
    # Tautologies - always-true conditions
    (r'\bOR\b[\s\n]+1[\s\n]*=[\s\n]*1', 'TAUTOLOGY_OR'),
    (r'\bAND\b[\s\n]+1[\s\n]*=[\s\n]*1', 'TAUTOLOGY_AND'),
    
    # Time-based blind injection
    (r'\bSLEEP\b[\s\n]*\(', 'TIME_SLEEP'),
    (r'\bWAITFOR\b[\s\n]+\bDELAY\b', 'TIME_WAITFOR'),
    (r'\bBENCHMARK\b[\s\n]*\(', 'TIME_BENCHMARK'),
]

# Advanced patterns (optional, higher false positive rate)
# Uncomment to enable more aggressive detection
ADVANCED_PATTERNS = [
    # Dangerous keywords (can have legitimate uses in admin tools)
    # (r'\bDROP\b[\s\n]+\bTABLE\b', 'DROP_TABLE'),
    # (r'\bDELETE\b[\s\n]+\bFROM\b', 'DELETE_FROM'),
    # (r'\bTRUNCATE\b[\s\n]+\bTABLE\b', 'TRUNCATE_TABLE'),
    
    # Information schema (normal in admin queries)
    # (r'\binformation_schema\b', 'INFO_SCHEMA'),
    # (r'\bsys\.', 'SYS_SCHEMA'),
    
    # Hex encoding (normal for binary data)
    # (r'0x[0-9a-fA-F]{4,}', 'HEX_ENCODING'),
]

# Compile patterns for efficiency
COMPILED_PATTERNS = [(re.compile(pattern, re.IGNORECASE | re.MULTILINE), rule_id) 
                     for pattern, rule_id in SQL_INJECTION_PATTERNS]


def normalize_string(s: str) -> str:
    """
    Normalize a string for SQL injection detection.
    - Collapse repeated whitespace
    - Convert to lowercase for case-insensitive matching
    """
    # Collapse whitespace (spaces, tabs, newlines) to single space
    normalized = re.sub(r'\s+', ' ', s)
    return normalized.lower()


def compute_query_hash(query: str) -> str:
    """
    Compute a short hash of the query for correlation without logging sensitive data.
    """
    return hashlib.sha256(query.encode()).hexdigest()[:16]


def extract_all_strings(obj: Any, path: str = "") -> List[Tuple[str, str]]:
    """
    Recursively extract all string values from a nested structure.
    Returns list of (path, value) tuples for logging which field triggered detection.
    
    Args:
        obj: Object to scan (dict, list, or primitive)
        path: Current path in the object tree (for logging)
    
    Returns:
        List of (path, string_value) tuples
    """
    strings = []
    
    if isinstance(obj, dict):
        for key, value in obj.items():
            new_path = f"{path}.{key}" if path else key
            strings.extend(extract_all_strings(value, new_path))
    elif isinstance(obj, list):
        for idx, item in enumerate(obj):
            new_path = f"{path}[{idx}]"
            strings.extend(extract_all_strings(item, new_path))
    elif isinstance(obj, str):
        strings.append((path, obj))
    
    return strings


def detect_sql_injection(value: str, field_path: str = "") -> Tuple[bool, str, str]:
    """
    Detect SQL injection patterns in a string value.
    
    Args:
        value: The string value to analyze
        field_path: Path to this field in the arguments (for logging)
    
    Returns:
        Tuple of (is_malicious: bool, rule_id: str, category: str)
        - is_malicious: True if SQL injection detected, False if safe
        - rule_id: Identifier of the matched rule (for internal logging)
        - category: Coarse category for caller (e.g., "SQL_INJECTION_DETECTED")
    """
    if not value:
        return False, "", ""
    
    # Reject extremely long strings early
    if len(value) > MAX_STRING_LENGTH:
        return True, "STRING_TOO_LONG", "INVALID_INPUT"
    
    # Normalize for detection
    normalized = normalize_string(value)
    
    # Check each pattern
    for pattern, rule_id in COMPILED_PATTERNS:
        if pattern.search(normalized):
            return True, rule_id, "SQL_INJECTION_DETECTED"
    
    return False, "", ""


def analyze_arguments_for_sql_injection(arguments: Dict[str, Any]) -> Tuple[bool, str, str]:
    """
    Analyze all tool arguments for SQL injection attacks.
    Recursively scans all string values in the arguments structure.
    
    IMPORTANT: This analyzes the tool's arguments, NOT the original user prompt.
    The agent has already processed the user prompt. We're protecting the database
    tool from SQL injection by analyzing all string parameters before execution.
    
    Args:
        arguments: The tool's arguments dict to analyze for SQL injection
    
    Returns:
        Tuple of (is_safe: bool, rule_id: str, category: str)
        - is_safe: True if arguments are safe, False if SQL injection detected
        - rule_id: Internal rule identifier (for logging only)
        - category: Coarse category for caller
    """
    # Extract all strings from arguments
    all_strings = extract_all_strings(arguments)
    
    if not all_strings:
        return True, "", ""
    
    # Check each string value
    for field_path, value in all_strings:
        is_malicious, rule_id, category = detect_sql_injection(value, field_path)
        
        if is_malicious:
            # Log detection without exposing the actual content
            value_hash = compute_query_hash(value)
            print(f"[SECURITY] SQL injection detected | field={field_path} | rule={rule_id} | hash={value_hash}")
            return False, rule_id, category
    
    return True, "", ""

def create_blocked_response(category: str, request_id: Any) -> Dict[str, Any]:
    """
    Create an MCP error response for blocked requests.
    
    For REQUEST interceptors, when blocking a request, we return a transformedGatewayResponse
    to short-circuit the request and send an error back to the client without calling the target.
    
    SECURITY: Returns only generic error message to caller. Detailed rule_id is logged only.
    
    Args:
        category: Coarse category (e.g., "SQL_INJECTION_DETECTED", "INVALID_INPUT")
        request_id: Original request ID from MCP request
    
    Returns:
        Interceptor response with transformedGatewayResponse containing error
    """
    # Generic message - do not expose detection details to caller
    generic_message = "Request blocked by security policy"
    
    blocked_response = {
        "interceptorOutputVersion": "1.0",
        "mcp": {
            "transformedGatewayResponse": {
                "statusCode": 403,  # Forbidden
                "headers": {
                    "Content-Type": "application/json",
                    "X-Security-Status": "BLOCKED"
                },
                "body": {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "error": {
                        "code": -32000,  # Server error code
                        "message": generic_message,
                        "data": {
                            "category": category,
                            "security_policy": "sql_injection_prevention"
                        }
                    }
                }
            }
        }
    }
    
    return blocked_response


def lambda_handler(event, context):
    """
    Main Lambda handler for Gateway REQUEST interceptor.
    
    This handler analyzes incoming tool requests for SQL injection attacks
    before they reach the database tools.
    
    IMPORTANT: This protects at the TOOL LEVEL by analyzing tool arguments.
    - The agent has already processed the user prompt
    - We're analyzing the tool's arguments for SQL injection
    - This prevents malicious queries from reaching the database
    
    Expected event structure (from Gateway REQUEST for tools/call):
    {
        "interceptorInputVersion": "1.0",
        "mcp": {
            "gatewayRequest": {
                "headers": {"Authorization": "Bearer ..."},
                "body": {
                    "jsonrpc": "2.0",
                    "method": "tools/call",
                    "id": "request-id",
                    "params": {
                        "name": "tool-name",
                        "arguments": {"query": "SELECT * FROM customers WHERE id = 123"}
                    }
                }
            }
        }
    }
    
    Returns either:
    - Original request (if safe) to proceed to tool
    - Blocked error response (if SQL injection detected or analysis fails)
    """
    try:
        # Extract MCP data
        mcp_data = event.get('mcp', {})
        gateway_request = mcp_data.get('gatewayRequest', {})
        request_body = gateway_request.get('body', {})
        
        method = request_body.get('method', '')
        request_id = request_body.get('id', 'unknown')
        
        # Log minimal info - no PII, no tokens, no SQL
        print(f"[INFO] Interceptor invoked | request_id={request_id} | method={method}")
        
        # Only analyze tools/call requests
        if method != 'tools/call':
            print(f"[INFO] Method not tools/call, passing through | request_id={request_id}")
            return {
                "interceptorOutputVersion": "1.0",
                "mcp": {
                    "transformedGatewayRequest": {
                        "headers": gateway_request.get('headers', {}),
                        "body": request_body
                    }
                }
            }
        
        # Extract tool call parameters
        params = request_body.get('params', {})
        tool_name = params.get('name', '')
        arguments = params.get('arguments', {})
        
        print(f"[INFO] Analyzing tool call | request_id={request_id} | tool={tool_name}")
        
        # STRICT MODE: Deny any raw SQL fields
        if STRICT_MODE:
            # Check if arguments contain raw SQL field
            if 'query' in arguments or 'sql' in arguments:
                print(f"[SECURITY] STRICT MODE: Raw SQL field rejected | request_id={request_id} | tool={tool_name}")
                return create_blocked_response("RAW_SQL_NOT_ALLOWED", request_id)
        
        # Analyze all string arguments for SQL injection
        is_safe, rule_id, category = analyze_arguments_for_sql_injection(arguments)
        
        if is_safe:
            print(f"[INFO] Request allowed | request_id={request_id} | tool={tool_name}")
            
            # Pass through original request unchanged
            return {
                "interceptorOutputVersion": "1.0",
                "mcp": {
                    "transformedGatewayRequest": {
                        "headers": gateway_request.get('headers', {}),
                        "body": request_body
                    }
                }
            }
        else:
            print(f"[SECURITY] Request blocked | request_id={request_id} | tool={tool_name} | rule={rule_id}")
            
            # Return blocked error response (generic message to caller)
            return create_blocked_response(category, request_id)
    
    except Exception as e:
        # Fail CLOSED: Block on any unexpected error
        print(f"[ERROR] Interceptor error | request_id={request_body.get('id', 'unknown')} | error={str(e)[:100]}")
        
        # Block request with generic error
        return create_blocked_response(
            "INTERCEPTOR_ERROR",
            request_body.get('id', 'unknown')
        )

