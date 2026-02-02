"""
Prompt Injection Prevention Interceptor for Gateway MCP REQUESTS using Bedrock Guardrails

This Lambda function intercepts Gateway MCP tools/call REQUESTS and analyzes
user prompts for injection attacks using Amazon Bedrock Guardrails before allowing
requests to reach tools. It is configured as a REQUEST interceptor.

This implementation uses Bedrock Guardrails' prompt attack detection capabilities
to identify and block malicious prompts including jailbreak attempts, prompt injection,
and other adversarial inputs.

Security: Fails CLOSED - blocks requests if Guardrails analysis fails or detects threats.
"""

import json
import os
import boto3
from typing import Any, Dict, Tuple

# Initialize Bedrock Runtime client
bedrock_runtime = boto3.client('bedrock-runtime')

# Get Guardrail configuration from environment variables
GUARDRAIL_ID = os.environ.get('GUARDRAIL_ID')
GUARDRAIL_VERSION = os.environ.get('GUARDRAIL_VERSION', 'DRAFT')

def analyze_prompt_with_guardrails(user_query: str) -> Tuple[bool, str]:
    """
    Use Amazon Bedrock Guardrails to analyze user prompt for injection attacks.
    
    Args:
        user_query: The user's input query to analyze
    
    Returns:
        Tuple of (is_safe: bool, reason: str)
        - is_safe: True if query is safe, False if injection detected
        - reason: Explanation of the security decision
    """
    print(f"[DEBUG] analyze_prompt_with_guardrails - INPUT query (first 200 chars): {user_query[:200]}")
    
    if not GUARDRAIL_ID:
        print("[DEBUG] WARNING: GUARDRAIL_ID not configured, blocking request (fail-closed)")
        print(f"[DEBUG] analyze_prompt_with_guardrails - RETURNING False (no guardrail)")
        return False, "Guardrail not configured"
    
    try:
        print(f"[DEBUG] Calling Bedrock Guardrails API with ID: {GUARDRAIL_ID}, Version: {GUARDRAIL_VERSION}")
        
        # Apply guardrail to the user input
        response = bedrock_runtime.apply_guardrail(
            guardrailIdentifier=GUARDRAIL_ID,
            guardrailVersion=GUARDRAIL_VERSION,
            source='INPUT',  # We're filtering user input
            content=[{
                'text': {
                    'text': user_query
                }
            }]
        )
        
        print(f"[DEBUG] Guardrails API response received: {json.dumps(response, default=str)}")
        
        # Check the action taken by the guardrail
        action = response.get('action', 'NONE')
        print(f"[DEBUG] Guardrail action: {action}")
        
        if action == 'GUARDRAIL_INTERVENED':
            # Guardrail detected a threat
            print(f"[DEBUG] Threat detected by Guardrails")
            
            # Extract details about what was detected
            assessments = response.get('assessments', [])
            reasons = []
            
            if assessments:
                for assessment in assessments:
                    # Check for prompt attack detection
                    prompt_attack = assessment.get('promptAttack', {})
                    if prompt_attack:
                        detected_types = []
                        if prompt_attack.get('jailbreak'):
                            detected_types.append('jailbreak attempt')
                        if prompt_attack.get('promptInjection'):
                            detected_types.append('prompt injection')
                        
                        if detected_types:
                            reasons.append(f"Detected: {', '.join(detected_types)}")
                            print(f"[DEBUG]   Detected threat types: {', '.join(detected_types)}")
                    
                    # Check for other policy violations
                    content_policy = assessment.get('contentPolicy', {})
                    if content_policy.get('filters'):
                        for filter_item in content_policy['filters']:
                            if filter_item.get('action') == 'BLOCKED':
                                filter_type = filter_item.get('type', 'unknown')
                                reasons.append(f"Content policy violation: {filter_type}")
                                print(f"[DEBUG]   Content policy violation: {filter_type}")
            
            reason = '; '.join(reasons) if reasons else "Potential security threat detected"
            print(f"[DEBUG] analyze_prompt_with_guardrails - RETURNING False (threat detected)")
            return False, reason
        
        elif action == 'NONE':
            # No intervention needed - query is safe
            print(f"[DEBUG] No threats detected by Guardrails")
            print(f"[DEBUG] analyze_prompt_with_guardrails - RETURNING True (safe)")
            return True, "Query passed security analysis"
        
        else:
            # Unexpected action - fail closed
            print(f"[DEBUG] WARNING: Unexpected guardrail action: {action}")
            print(f"[DEBUG] analyze_prompt_with_guardrails - RETURNING False (unexpected action)")
            return False, f"Unexpected security response: {action}"
        
    except Exception as e:
        # Fail CLOSED: Block on any error for security
        error_message = str(e)
        print(f"[DEBUG] ERROR applying Guardrails: {error_message}")
        print(f"[DEBUG]   Guardrail ID: {GUARDRAIL_ID}")
        print(f"[DEBUG]   Guardrail Version: {GUARDRAIL_VERSION}")
        
        # Check if it's a validation error about guardrail not existing
        if 'does not exist' in error_message or 'ValidationException' in error_message:
            print("[DEBUG]   ⚠ The Guardrail ID or version is invalid or doesn't exist")
            print("[DEBUG]   ⚠ Make sure Step 1.3 was run successfully to create the Guardrail")
            print("[DEBUG]   ⚠ Verify the Lambda environment variables are set correctly")
        
        # On error, block request (fail closed for security)
        print(f"[DEBUG] analyze_prompt_with_guardrails - RETURNING False (error occurred)")
        return False, f"Security analysis failed: {error_message[:100]}"

def create_blocked_response(reason: str, request_id: Any, request_headers: Dict[str, Any]) -> Dict[str, Any]:
    """
    Create an MCP error response for blocked requests.
    
    For REQUEST interceptors, when blocking a request, we return a transformedGatewayResponse
    to short-circuit the request and send an error back to the client without calling the target.
    
    Args:
        reason: Explanation for why request was blocked
        request_id: Original request ID from MCP request
        request_headers: Original request headers
    
    Returns:
        Interceptor response with transformedGatewayResponse containing error
    """
    print(f"[DEBUG] create_blocked_response - Creating blocked response")
    print(f"[DEBUG]   Request ID: {request_id}")
    print(f"[DEBUG]   Reason: {reason}")
    
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
                        "message": "Request blocked by security interceptor",
                        "data": {
                            "reason": reason,
                            "security_policy": "prompt_injection_prevention"
                        }
                    }
                }
            }
        }
    }
    
    print(f"[DEBUG] create_blocked_response - RETURNING blocked response")
    return blocked_response


def lambda_handler(event, context):
    """
    Main Lambda handler for Gateway REQUEST interceptor.
    
    This handler analyzes incoming tool requests for prompt injection attacks
    before they reach the target tools using Bedrock Guardrails.
    
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
                        "arguments": {"query": "user input here"}
                    }
                }
            }
        }
    }
    
    Returns either:
    - Original request (if safe) to proceed to tool
    - Blocked error response (if unsafe or analysis fails)
    """
    print(f"[DEBUG] ========== LAMBDA HANDLER START ==========")
    print(f"[DEBUG] Prompt Injection Prevention Interceptor - Received event: {json.dumps(event, default=str)}")
    
    try:
        # Extract MCP data
        mcp_data = event.get('mcp', {})
        print(f"[DEBUG] Extracted mcp_data: {json.dumps(mcp_data, default=str)}")
        
        gateway_request = mcp_data.get('gatewayRequest', {})
        print(f"[DEBUG] Extracted gateway_request: {json.dumps(gateway_request, default=str)}")
        
        # Get request data
        request_headers = gateway_request.get('headers', {})
        print(f"[DEBUG] request_headers: {request_headers}")
        
        request_body = gateway_request.get('body', {})
        print(f"[DEBUG] request_body: {json.dumps(request_body, default=str)}")
        
        method = request_body.get('method', '')
        print(f"[DEBUG] Method: {method}")
        
        request_id = request_body.get('id', 'unknown')
        print(f"[DEBUG] Request ID: {request_id}")
        
        # Only analyze tools/call requests
        if method != 'tools/call':
            print(f"[DEBUG] Method is not 'tools/call', passing through unchanged")
            
            passthrough_obj = {
                "interceptorOutputVersion": "1.0",
                "mcp": {
                    "transformedGatewayRequest": {
                        "headers": request_headers,
                        "body": request_body
                    }
                }
            }
            
            print(f"[DEBUG] lambda_handler - RETURNING (passthrough): {json.dumps(passthrough_obj, default=str)}")
            print(f"[DEBUG] ========== LAMBDA HANDLER END (passthrough) ==========")
            return passthrough_obj
        
        # Extract tool call parameters
        params = request_body.get('params', {})
        tool_name = params.get('name', '')
        arguments = params.get('arguments', {})
        
        print(f"[DEBUG] Tool called: {tool_name}")
        print(f"[DEBUG] Arguments: {json.dumps(arguments, default=str)}")
        
        # Extract user query from arguments
        # Adjust this based on your tool's argument structure
        user_query = arguments.get('query', '')
        
        if not user_query:
            print(f"[DEBUG] No 'query' argument found, passing through")
            
            passthrough_obj = {
                "interceptorOutputVersion": "1.0",
                "mcp": {
                    "transformedGatewayRequest": {
                        "headers": request_headers,
                        "body": request_body
                    }
                }
            }
            
            print(f"[DEBUG] lambda_handler - RETURNING (no query): {json.dumps(passthrough_obj, default=str)}")
            print(f"[DEBUG] ========== LAMBDA HANDLER END (no query) ==========")
            return passthrough_obj
        
        print(f"[DEBUG] Analyzing user query for injection attacks...")
        
        # Analyze query with Bedrock Guardrails
        is_safe, reason = analyze_prompt_with_guardrails(user_query)
        
        if is_safe:
            print(f"[DEBUG] Query is SAFE - allowing request to proceed")
            print(f"[DEBUG] Reason: {reason}")
            
            # Pass through original request unchanged
            safe_obj = {
                "interceptorOutputVersion": "1.0",
                "mcp": {
                    "transformedGatewayRequest": {
                        "headers": request_headers,
                        "body": request_body
                    }
                }
            }
            
            print(f"[DEBUG] lambda_handler - RETURNING (safe): {json.dumps(safe_obj, default=str)}")
            print(f"[DEBUG] ========== LAMBDA HANDLER END (safe) ==========")
            return safe_obj
        else:
            print(f"[DEBUG] Query is UNSAFE - BLOCKING request")
            print(f"[DEBUG] Reason: {reason}")
            
            # Return blocked error response
            blocked_obj = create_blocked_response(reason, request_id, request_headers)
            
            print(f"[DEBUG] lambda_handler - RETURNING (blocked): {json.dumps(blocked_obj, default=str)}")
            print(f"[DEBUG] ========== LAMBDA HANDLER END (blocked) ==========")
            return blocked_obj
    
    except Exception as e:
        print(f"[DEBUG] ERROR in lambda_handler: {e}")
        
        import traceback
        print(f"[DEBUG] Traceback: {traceback.format_exc()}")
        
        # Fail CLOSED: Block on any unexpected error
        print(f"[DEBUG] BLOCKING request due to interceptor error (fail-closed)")
        
        error_obj = create_blocked_response(
            f"Interceptor error: {str(e)[:100]}",
            request_body.get('id', 'unknown'),
            gateway_request.get('headers', {})
        )
        
        print(f"[DEBUG] lambda_handler - RETURNING (error): {json.dumps(error_obj, default=str)}")
        print(f"[DEBUG] ========== LAMBDA HANDLER END (error) ==========")
        return error_obj

