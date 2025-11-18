#!/usr/bin/env python3
"""
alphaMountain MCP Server

An MCP (Model Context Protocol) server for the alphaMountain.ai API.
Provides threat intelligence, URL categorization, and domain intelligence tools.
"""

import argparse
import logging
import os
import json
from typing import Optional, List, Dict, Any
import requests
from mcp.server.fastmcp import FastMCP

# Configure module-level logger
logger = logging.getLogger(__name__)

# Create the main FastMCP instance
mcp = FastMCP("alphaMountain-MCP")

# API Configuration
API_BASE_URL = "https://api.alphamountain.ai"
BATCH_BASE_URL = "https://batch.alphamountain.ai"
API_VERSION = 1

# Get API key from environment variable
API_KEY = os.getenv("ALPHAMOUNTAIN_API_KEY", "")


def make_api_request(
    endpoint: str,
    data: Dict[str, Any],
    base_url: str = API_BASE_URL,
    api_key: Optional[str] = None
) -> Dict[str, Any]:
    """
    Make a POST request to the alphaMountain API.
    
    Args:
        endpoint: API endpoint path (e.g., '/threat/uri')
        data: Request payload dictionary
        base_url: Base URL for the API (default: API_BASE_URL)
        api_key: API key to use (default: from environment or global)
    
    Returns:
        Response JSON as dictionary
    
    Raises:
        requests.RequestException: If the API request fails
    """
    if api_key is None:
        api_key = API_KEY
    
    if not api_key:
        raise ValueError("API key is required. Set ALPHAMOUNTAIN_API_KEY environment variable or pass api_key parameter.")
    
    # Ensure required fields are present
    data["license"] = api_key
    data["version"] = API_VERSION
    if "type" not in data:
        data["type"] = "partner.info"
    
    url = f"{base_url}{endpoint}"
    headers = {"Content-Type": "application/json"}
    
    try:
        response = requests.post(url, headers=headers, json=data, timeout=30)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.HTTPError as e:
        error_msg = f"HTTP {response.status_code}: {response.text}"
        logger.error(error_msg)
        raise Exception(error_msg) from e
    except requests.exceptions.RequestException as e:
        logger.error(f"Request failed: {e}")
        raise


# URL Threat Intelligence Tools
@mcp.tool()
def get_threat_score(
    uri: str,
    scan_depth: str = "low",
    api_key: Optional[str] = None
) -> Dict[str, Any]:
    """
    Get threat score for a single URL/URI.
    
    Args:
        uri: The URI or URL to assess (e.g., 'https://google.com/')
        scan_depth: Scan depth - one of 'none', 'low', 'medium', or 'high' (default: 'low')
        api_key: Optional API key (defaults to ALPHAMOUNTAIN_API_KEY env var)
    
    Returns:
        Dictionary containing threat score, scope, source, and TTL
    """
    data = {
        "uri": uri,
        "scan_depth": scan_depth
    }
    return make_api_request("/threat/uri", data, api_key=api_key)


@mcp.tool()
def get_threat_scores(
    uris: List[str],
    api_key: Optional[str] = None
) -> Dict[str, Any]:
    """
    Get threat scores for multiple URLs/URIs.
    
    Args:
        uris: List of URIs or URLs to assess (e.g., ['http://example.com/', 'https://google.com/'])
        api_key: Optional API key (defaults to ALPHAMOUNTAIN_API_KEY env var)
    
    Returns:
        Dictionary containing scores and errors for each URI
    """
    data = {"uris": uris}
    return make_api_request("/threat/uris", data, api_key=api_key)


# URL Categorization Tools
@mcp.tool()
def get_categories(
    uri: str,
    api_key: Optional[str] = None
) -> Dict[str, Any]:
    """
    Get categories for a single URL/URI.
    
    Args:
        uri: The URI or URL to categorize (e.g., 'https://google.com/')
        api_key: Optional API key (defaults to ALPHAMOUNTAIN_API_KEY env var)
    
    Returns:
        Dictionary containing categories, confidence, scope, and TTL
    """
    data = {"uri": uri}
    return make_api_request("/category/uri", data, api_key=api_key)


@mcp.tool()
def get_categories_batch(
    uris: List[str],
    api_key: Optional[str] = None
) -> Dict[str, Any]:
    """
    Get categories for multiple URLs/URIs.
    
    Args:
        uris: List of URIs or URLs to categorize (e.g., ['http://google.com/', 'https://example.com/'])
        api_key: Optional API key (defaults to ALPHAMOUNTAIN_API_KEY env var)
    
    Returns:
        Dictionary containing categories and errors for each URI
    """
    data = {"uris": uris}
    return make_api_request("/category/uris", data, api_key=api_key)


# Domain Intelligence Tools
@mcp.tool()
def get_hostname_intelligence(
    hostname: str,
    sections: List[str],
    limit: Optional[int] = None,
    api_key: Optional[str] = None
) -> Dict[str, Any]:
    """
    Get intelligence data for a domain/hostname.
    
    Args:
        hostname: The domain/hostname to gather intelligence on (e.g., 'google.com')
        sections: List of intelligence sections to gather. Options:
            - 'dga': Domain generation algorithm probability
            - 'dns': DNS records (A, AAAA, NS, MX, TXT, DMARC, DKIM)
            - 'geo': Geolocation of resolved IPs
            - 'impersonate': List of possibly impersonated domains
            - 'pdns': Passive DNS
            - 'popularity': Current domain ranking
            - 'relations_links': Inbound and outbound links
            - 'relations_redirects': Inbound and outbound redirects
            - 'relations_same_ip': Hosts on the same IP(s)
            - 'relations_same_domain': Hosts on the same domain
            - 'relations_content_security_policy': Hosts in CSP header
            - 'relations_certificate_altnames': Hosts in certificate altnames
            - 'scan_screenshot': Screenshot of the domain
            - 'scan_response': Analysis of http(s) response
            - 'scan_dom': Raw http(s) HTML documents
            - 'scan_ports': Analysis of open ports
            - 'whois': Raw whois record and parsed values
        limit: Optional limit on number of records returned
        api_key: Optional API key (defaults to ALPHAMOUNTAIN_API_KEY env var)
    
    Returns:
        Dictionary containing intelligence data for requested sections
    """
    data = {
        "hostname": hostname,
        "sections": sections
    }
    if limit is not None:
        data["limit"] = limit
    
    return make_api_request("/intelligence/hostname", data, api_key=api_key)


# Feed Tools
@mcp.tool()
def get_threat_feed_json(
    limit: Optional[int] = None,
    risk_min: Optional[int] = None,
    risk_max: Optional[int] = None,
    start: Optional[str] = None,
    flags: Optional[List[str]] = None,
    api_key: Optional[str] = None
) -> Dict[str, Any]:
    """
    Get new and revalidated threat ratings in JSON format.
    
    Args:
        limit: Limit on number of records (defaults to license entitlements)
        risk_min: Minimum risk score to include (defaults to license entitlements)
        risk_max: Maximum risk score to include (defaults to license entitlements)
        start: ISO8601 timestamp for beginning of records to fetch
        flags: Optional flags: 'exclude-ip', 'exclude-host', 'exclude-path', 'exclude-dead', 'include-removals'
        api_key: Optional API key (defaults to ALPHAMOUNTAIN_API_KEY env var)
    
    Returns:
        Dictionary containing feed array with threat scores
    """
    data = {}
    if limit is not None:
        data["limit"] = limit
    if risk_min is not None:
        data["risk_min"] = risk_min
    if risk_max is not None:
        data["risk_max"] = risk_max
    if start:
        data["start"] = start
    if flags:
        data["flags"] = flags
    
    return make_api_request("/threat/feed/json", data, base_url=BATCH_BASE_URL, api_key=api_key)


@mcp.tool()
def get_category_feed_json(
    limit: Optional[int] = None,
    categories: Optional[List[int]] = None,
    start: Optional[str] = None,
    flags: Optional[List[str]] = None,
    api_key: Optional[str] = None
) -> Dict[str, Any]:
    """
    Get new and revalidated content categorization in JSON format.
    
    Args:
        limit: Limit on number of records (defaults to license entitlements)
        categories: List of category IDs to include (defaults to license entitlements)
        start: ISO8601 timestamp for beginning of records to fetch
        flags: Optional flags: 'exclude-ip', 'exclude-host', 'exclude-path', 'exclude-dead', 'include-removals'
        api_key: Optional API key (defaults to ALPHAMOUNTAIN_API_KEY env var)
    
    Returns:
        Dictionary containing feed array with category data
    """
    data = {}
    if limit is not None:
        data["limit"] = limit
    if categories:
        data["categories"] = categories
    if start:
        data["start"] = start
    if flags:
        data["flags"] = flags
    
    return make_api_request("/category/feed/json", data, base_url=BATCH_BASE_URL, api_key=api_key)


@mcp.tool()
def get_popularity_feed_json(
    limit: Optional[int] = None,
    api_key: Optional[str] = None
) -> Dict[str, Any]:
    """
    Get current host popularity rankings in JSON format.
    
    Args:
        limit: Limit on number of records (defaults to 1M)
        api_key: Optional API key (defaults to ALPHAMOUNTAIN_API_KEY env var)
    
    Returns:
        Dictionary containing feed array with popularity rankings
    """
    data = {}
    if limit is not None:
        data["limit"] = limit
    
    return make_api_request("/popularity/feed/json", data, base_url=BATCH_BASE_URL, api_key=api_key)


# Accounting Tools
@mcp.tool()
def get_quota(
    endpoint: str,
    api_key: Optional[str] = None
) -> Dict[str, Any]:
    """
    Fetch remaining quota for a specific endpoint.
    
    Args:
        endpoint: One of 'category', 'threat', 'impersonate', 'popularity', 'batch/category', or 'batch/threat'
        api_key: Optional API key (defaults to ALPHAMOUNTAIN_API_KEY env var)
    
    Returns:
        Dictionary containing quota information (remaining, expiry, daily/monthly quotas)
    """
    data = {"endpoint": endpoint}
    return make_api_request("/quota", data, api_key=api_key)


@mcp.tool()
def get_license_info(
    flags: Optional[List[str]] = None,
    api_key: Optional[str] = None
) -> Dict[str, Any]:
    """
    Fetch detailed license and service information.
    
    Args:
        flags: Optional flags: 'include-expired' to include expired licenses
        api_key: Optional API key (defaults to ALPHAMOUNTAIN_API_KEY env var)
    
    Returns:
        Dictionary containing comprehensive license information for all services
    """
    data = {}
    if flags:
        data["flags"] = flags
    
    return make_api_request("/license/info", data, api_key=api_key)


# Support Tools
@mcp.tool()
def submit_dispute(
    uri: str,
    dispute_type: str,
    email: str,
    scope: Optional[str] = None,
    risk_score: Optional[float] = None,
    categories: Optional[List[int]] = None,
    source: Optional[str] = None,
    severity: Optional[int] = None,
    notes: Optional[str] = None,
    name: Optional[str] = None,
    api_key: Optional[str] = None
) -> Dict[str, Any]:
    """
    Submit a dispute for a URI in the alphaMountain database.
    
    Args:
        uri: The URI being disputed (required)
        dispute_type: Type of dispute - 'FP' (False Positive) or 'FN' (False Negative) (required)
        email: Email address for the dispute (required)
        scope: Optional scope - 'domain' or 'path'
        risk_score: Optional suggested risk score (1-10)
        categories: Optional list of suggested category IDs
        source: Optional source - 'internal', 'partner', or 'customer'
        severity: Optional severity 1-4 (1 being most severe)
        notes: Optional notes for the dispute
        name: Optional name for the dispute
        api_key: Optional API key (defaults to ALPHAMOUNTAIN_API_KEY env var)
    
    Returns:
        Dictionary containing ticket_id for the dispute
    """
    data = {
        "uri": uri,
        "type": dispute_type,
        "email": email
    }
    
    if scope:
        data["scope"] = scope
    if risk_score is not None:
        data["risk_score"] = risk_score
    if categories:
        data["categories"] = categories
    if source:
        data["source"] = source
    if severity is not None:
        data["severity"] = severity
    if notes:
        data["notes"] = notes
    if name:
        data["name"] = name
    
    return make_api_request("/support/dispute", data, api_key=api_key)


@mcp.tool()
def get_dispute_status(
    ticket_id: str,
    api_key: Optional[str] = None
) -> Dict[str, Any]:
    """
    Fetch the status of a dispute by ticket ID.
    
    Args:
        ticket_id: The ticket ID of the dispute (required)
        api_key: Optional API key (defaults to ALPHAMOUNTAIN_API_KEY env var)
    
    Returns:
        Dictionary containing dispute status information
    """
    data = {"ticket_id": ticket_id}
    return make_api_request("/support/dispute/status", data, api_key=api_key)


def main():
    """Main entry point for the MCP server."""
    parser = argparse.ArgumentParser(description="alphaMountain MCP Server")
    parser.add_argument(
        "--mcp-host",
        type=str,
        default="127.0.0.1",
        help="Host to run MCP server on (only used for sse), default: 127.0.0.1"
    )
    parser.add_argument(
        "--mcp-port",
        type=int,
        help="Port to run MCP server on (only used for sse), default: 8081"
    )
    parser.add_argument(
        "--transport",
        type=str,
        default="sse",
        choices=["stdio", "sse"],
        help="Transport protocol for MCP, default: sse"
    )
    parser.add_argument(
        "--api-key",
        type=str,
        help="alphaMountain API key (overrides ALPHAMOUNTAIN_API_KEY env var)"
    )
    args = parser.parse_args()
    
    # Set API key if provided via command line
    global API_KEY
    if args.api_key:
        API_KEY = args.api_key
    
    # Check if API key is set
    if not API_KEY:
        logger.warning(
            "No API key found. Set ALPHAMOUNTAIN_API_KEY environment variable "
            "or use --api-key flag. Some tools may fail without an API key."
        )
    
    # Use Server-Sent Events (SSE) transport
    if args.transport == "sse":
        try:
            # Configure basic logging at INFO level
            log_level = logging.INFO
            logging.basicConfig(level=log_level)
            logging.getLogger().setLevel(log_level)
            
            # Apply FastMCP settings based on arguments
            mcp.settings.log_level = "INFO"
            mcp.settings.host = args.mcp_host or "127.0.0.1"
            mcp.settings.port = args.mcp_port or 8081
            
            logger.info(f"Starting alphaMountain MCP server on http://{mcp.settings.host}:{mcp.settings.port}/sse")
            logger.info(f"Using transport: {args.transport}")
            if API_KEY:
                logger.info("API key is configured")
            else:
                logger.warning("API key is not configured")
            
            # Start the MCP server with SSE transport
            mcp.run(transport="sse")
        except KeyboardInterrupt:
            logger.info("Server stopped by user")
    else:
        # Run MCP in stdio transport mode
        mcp.run()


if __name__ == "__main__":
    main()

