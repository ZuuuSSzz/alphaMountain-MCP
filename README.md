# alphaMountain MCP Server

An MCP (Model Context Protocol) server for the [alphaMountain.ai](https://alphamountain.ai) API, providing threat intelligence, URL categorization, and domain intelligence tools.

## Features

This MCP server exposes the following alphaMountain API endpoints as tools:

### URL Threat Intelligence
- `get_threat_score` - Get threat score for a single URL
- `get_threat_scores` - Get threat scores for multiple URLs

### URL Categorization
- `get_categories` - Get categories for a single URL
- `get_categories_batch` - Get categories for multiple URLs

### Domain Intelligence
- `get_hostname_intelligence` - Get comprehensive intelligence data for a domain/hostname

### Feeds
- `get_threat_feed_json` - Get threat ratings feed in JSON format
- `get_category_feed_json` - Get categorization feed in JSON format
- `get_popularity_feed_json` - Get popularity rankings feed in JSON format

### Accounting
- `get_quota` - Fetch remaining quota for an endpoint
- `get_license_info` - Get detailed license and service information

### Support
- `submit_dispute` - Submit a dispute for a URI
- `get_dispute_status` - Get the status of a dispute

## Prerequisites

- **Python 3.7+**
- **alphaMountain API Key** - [Request a free trial key](https://www.alphamountain.ai/threat-intelligence-feeds-api/)

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/ZuuuSSzz/alphaMountain-MCP
cd alphaMountain-MCP
```

### 2. Create a virtual environment (recommended)

```bash
python -m venv venv
source venv/bin/activate    # Linux/macOS
venv\Scripts\activate      # Windows
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

## Configuration

### Set API Key

You can set your alphaMountain API key in one of the following ways:

1. **Environment Variable (Recommended for standalone usage)**
   ```bash
   export ALPHAMOUNTAIN_API_KEY="your-api-key-here"
   ```

2. **In MCP Configuration File (Recommended for Cursor/Claude Desktop)**
   - See [Integration with Cursor/Claude Desktop](#integration-with-cursorclaude-desktop) section below

3. **Command Line Argument**
   ```bash
   python alphamountain_mcp.py --api-key "your-api-key-here"
   ```

4. **Pass to individual tools** - Each tool accepts an optional `api_key` parameter

## Usage

### Run the MCP Server

#### Using SSE Transport (default)

```bash
python alphamountain_mcp.py --mcp-host 127.0.0.1 --mcp-port 8081 --transport sse
```

#### Using stdio Transport

```bash
python alphamountain_mcp.py --transport stdio
```

### Command Line Options

- `--mcp-host`: Host to run MCP server on (default: `127.0.0.1`, only used for SSE)
- `--mcp-port`: Port to run MCP server on (default: `8081`, only used for SSE)
- `--transport`: Transport protocol - `sse` or `stdio` (default: `sse`)
- `--api-key`: alphaMountain API key (overrides environment variable)

## Example Usage

### Get Threat Score for a URL

```python
# Using the MCP tool
result = get_threat_score(
    uri="https://google.com/",
    scan_depth="low"
)
# Returns: {"version": 1, "status": {"threat": "Success"}, "threat": {"score": 1.10, ...}}
```

### Get Categories for Multiple URLs

```python
result = get_categories_batch(
    uris=["https://google.com/", "https://example.com/"]
)
```

### Get Domain Intelligence

```python
result = get_hostname_intelligence(
    hostname="google.com",
    sections=["popularity", "dns", "whois"]
)
```

### Check Quota

```python
result = get_quota(endpoint="threat")
# Returns: {"remaining": 8739, "key_expiry": "2022-12-31T00:00:00.000Z", ...}
```

## Integration with Cursor/Claude Desktop

To use this MCP server with Cursor or Claude Desktop, add it to your MCP configuration file:

### For Cursor

1. Open or create `~/.cursor/mcp.json` (or `%APPDATA%\Cursor\User\mcp.json` on Windows)

2. Add the following configuration (adjust the path to match your installation):

```json
{
  "mcpServers": {
    "alphamountain": {
      "command": "/path/to/alphamountain/venv/bin/python",
      "args": [
        "/path/to/alphamountain/alphamountain_mcp.py",
        "--transport",
        "stdio"
      ],
      "env": {
        "ALPHAMOUNTAIN_API_KEY": "your-api-key-here"
      }
    }
  }
}
```

**Note:** Replace `/path/to/alphamountain` with the actual path where you cloned this repository.

### For Claude Desktop

1. Open or create the MCP configuration file:
   - **macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`
   - **Windows**: `%APPDATA%\Claude\claude_desktop_config.json`

2. Add the same configuration as shown above for Cursor

3. Restart Cursor/Claude Desktop for the changes to take effect

The server will automatically start when the application launches and the tools will be available in your MCP client.

## API Documentation

For detailed API documentation, see the [alphaMountain API documentation](https://www.alphamountain.ai/threat-intelligence-feeds-api/) or refer to the `swagger.yaml.txt` file in this directory.

## Error Handling

The server handles common API errors:
- **401**: Unauthorized (invalid license)
- **429**: Quota exhausted (check `X-Quota-Next-Reset` header)
- **498**: Expired API key
- **4xx/5xx**: Other HTTP errors

All errors are logged and raised as exceptions with descriptive messages.


## License

This MCP server is provided as-is. The alphaMountain API service has its own terms and conditions.

## Support

For issues with:
- **This MCP Server**: Open an issue in the repository
- **alphaMountain API**: Contact [alphaMountain support](https://alphamountain.freshdesk.com/)
