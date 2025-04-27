# Project SNOW
![Main Image](https://github.com/thomasjjj/Telegram-Snowball-Sampling/assets/118008765/58cae690-b8cc-4b93-b073-809d888fe49e)

## Overview
Project SNOW is a Python-based utility designed for conducting snowball sampling to collect Telegram channels through forwards. This script uses the Telethon library to interact with Telegram's API, allowing for the automated discovery and processing of Telegram channels based on message forwards.

## Summary of Snowball Sampling in Telegram Network Analysis
Snowball sampling is a strategic methodology employed in network analysis, particularly effective for investigating populations that are otherwise difficult to observe directly. This method is especially useful in the context of Telegram, a social network where channels and chats serve as nodes. These nodes are interconnected through forwards, mentions, and internal hyperlinks, which function as the network edges.

### Concept and Application in Telegram
In Telegram's complex network, the structure is not readily observable externally – channels generally need to be found to search the messages within them. Snowball sampling is thus an invaluable technique for mapping this concealed network. It begins with a selected initial sample (or 'seed') and expands through multiple steps, identifying relevant actors within this network through message forwards. The seed channel is crucial as it sets the direction and scope of the sampling. However, the choice of the seed can introduce biases, influencing the resulting sample and network representation.

### Data Collection and Expansion
Data in this method are typically gathered using Telegram's "export chat history" function, however, this process connects through the Telegram API to allow the user to directly connect to Telegram and automate the process. This approach is known as exponential discriminative snowball sampling. It starts with a seed channel, often one with connections to specific interest groups or populations. The process involves collecting forwards from this channel, which reveals both the origin and dissemination paths of the information. This dual nature of forwards - identifying both the forwarder and the forwarded - creates a directed network structure.

### Methodological Considerations
While effective, this technique can introduce certain distortions due to the non-random nature of the seed selection. This aspect necessitates careful consideration, especially when discussing methodological limitations.

### Implementation Strategies
Various strategies are employed to determine the expansion of the sample. For instance, one approach involves selecting a set number of prominent channels based on metrics like forwards, mentions, or links. Another strategy counts the distinct channels referencing a particular channel, mitigating the undue influence of larger channels. A combined approach evaluates channels based on the number of distinct references, balancing between prominence and diversity. This method can lead to the collection of a significant number of channels and messages, offering a comprehensive view of the network under study.

## Important Warning: Runtime Expectations

### Exponential Growth in Runtime
The Project SNOW, while powerful, can potentially take several days (or drastically longer with more iterations) to complete its run. This extended runtime is due to the exponential nature of the snowball sampling process.

- **Exponential Process Explained**: In snowball sampling, each iteration potentially adds a new set of channels to be processed in the next iteration. For example, if each channel forwards messages from just three new channels, in the first iteration, you will process three channels, nine in the second iteration, and twenty-seven in the third iteration. This growth in the number of channels is exponential, meaning that each additional iteration can significantly increase the total number of channels to be processed, leading to a massive increase in runtime.

- **Impact of Additional Iterations**: Given this exponential growth, each additional iteration beyond the initial few can drastically increase the total runtime. Therefore, while the tool supports configuring the number of iterations, users should be mindful of this exponential increase in processing time.

### Recommendations for Efficient Use
- **Limit Iterations**: It's recommended to limit the process to three iterations for a balance between depth of search and practical runtime.
- **Filter Forwards**: To improve efficiency, consider filtering forwards to focus on channels that are commonly mentioned. This approach helps in targeting more relevant channels and reduces unnecessary processing.
- **Limit Posts Per Channel**: Another way to control runtime is by limiting the number of posts searched in each channel. This can significantly reduce the time taken per channel, especially for channels with a large number of posts.

## Architecture Overview

Project SNOW consists of several interconnected components:

### Core Components
1. **Main Module** (`main.py`): Entry point containing core sampling logic, message processing, and application control flow
2. **Database Manager** (`db_manager.py`): Manages persistent storage of data
3. **Cache Manager** (`cache_manager.py`): Handles caching and rate limiting of API calls
4. **Edge List** (`EdgeList.py`): Creates network edge lists for analysis
5. **Configuration** (`config.py` & `config.yaml`): Manages application settings
6. **Utilities** (`utils.py`): Contains helper functions and specialized components

### Terminal User Interface (TUI)
The application features a comprehensive Terminal User Interface built with npyscreen:

- **MainForm**: Primary interface for controlling the sampling process
- **ConfigForm**: Configuration management interface
- **PersistenceForm**: Session persistence management
- **FocusForm**: Focused analysis of specific channels or users
- **ElasticsearchForm**: Elasticsearch integration configuration
- **TgArchiveForm**: Interface for tg-archive integration
- **ProxyForm**: Proxy and VPN management

### ProxyManager
The `ProxyManager` class (in `utils.py`) provides robust proxy rotation and VPN integration:

```python
class ProxyManager:
    """Handles proxy rotation, validation, and VPN integration."""
    
    def __init__(self, proxy_file='proxy.txt', rotation_interval=300, validation_timeout=10):
        self.proxy_file = proxy_file
        self.rotation_interval = rotation_interval  # seconds
        self.validation_timeout = validation_timeout  # seconds
        self.proxies = []
        self.validated_proxies = []
        self.current_proxy = None
        self.last_rotation = 0
        self.vpn_provider = None
        self.vpn_credentials = {}
        self.vpn_connected = False
        self.lock = threading.Lock()
```

Features include:
- Loading and validating proxies from file
- Automatic proxy rotation
- Integration with VPN services (IPVanish, NordVPN)
- Connection monitoring and management

### CacheManager
The `CacheManager` class (in `cache_manager.py`) provides:

- Disk-based caching of API responses
- Rate limiting with exponential backoff
- Decorator functions for easy implementation
- TTL (Time-To-Live) management for cached items

### Database Architecture
The `DBManager` and `Database` classes (in `db_manager.py`) implement:

- SQLite database for persistent storage
- Schema versioning and migration support
- Transaction management with thread safety
- Comprehensive data models for channels, mentions, and metadata

## Features
- Automated collection of Telegram channels through snowball sampling
- Customizable iteration depth, mention thresholds, and message processing limits
- CSV output for easy analysis of collected data
- Terminal-based user interface (TUI) for easy configuration and monitoring
- Background operation via screen/tmux for SSH connections
- HMAC verification for enhanced API security
- Visualization of network relationships and channel categories
- Category-based filtering to focus on specific types of channels
- Time-based sampling to analyze content from specific date ranges
- Export to network analysis formats (GEXF, GraphML, JSON)
- Webhook notifications to monitor progress (Slack, Discord, etc.)
- Proxy rotation and VPN integration for improved anonymity
- Elasticsearch integration for advanced analytics
- tg-archive integration for creating static web archives

## Requirements
- Python 3.6 or higher
- Telethon library for Telegram API interaction
- A registered Telegram application (for API credentials)
- npyscreen for the Terminal User Interface
- Optional: screen or tmux for background operations (highly recommended for SSH sessions)

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/username/Project-SNOW.git
   cd Project-SNOW
   ```

2. Install the required dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Install screen or tmux (recommended for SSH sessions):
   ```bash
   # For Debian/Ubuntu
   sudo apt-get install screen
   # or
   sudo apt-get install tmux
   
   # For CentOS/RHEL
   sudo yum install screen
   # or
   sudo yum install tmux
   ```

4. Configure the application by editing `config.yaml` or using the TUI

## Security Features

The application includes several security features:

1. **HMAC Verification**: API requests are verified using HMAC tokens
2. **Encryption Key Rotation**: Regular rotation of encryption keys for enhanced security
3. **Secure Credential Storage**: API credentials are stored securely
4. **VPN Integration**: Optional VPN connectivity for anonymous operation

Example from SecurityConfig:
```python
def generate_hmac_token(self, message: str) -> str:
    """Generate an HMAC token for the given message"""
    key = hashlib.sha256(self.api_salt.encode()).digest()
    return hmac.new(
        key=key,
        msg=message.encode(),
        digestmod=hashlib.sha256
    ).hexdigest()
```

## Usage

### Starting via Terminal UI
```bash
python main.py
```
This will launch the Terminal UI where you can configure your sampling parameters and start the process.

### Focusing on a Specific User
To focus analysis on a specific Telegram user instead of a channel:

```bash
python main.py --focus-user username --focus-depth 3 --include-replies
```

Options:
- `--focus-user`: Target username to analyze
- `--focus-depth`: Maximum depth of analysis (default: 3)
- `--include-replies`: Include replies in the analysis
- `--include-forwards`: Include forwards in the analysis (enabled by default)

### Filtering by Category
To focus only on channels in specific categories:

```bash
python main.py --categories politics,technology,cybersecurity
```

This will only process channels that match the specified categories. The tool automatically categorizes channels based on their title and description.

### Time-Based Sampling
To analyze messages within a specific date range:

```bash
python main.py --date-start 2023-01-01 --date-end 2023-06-30
```

This will only process messages that were posted within the specified date range, allowing for focused temporal analysis.

### tg-archive Integration
To create static web archives of Telegram channels using tg-archive:

```bash
python main.py --tg-archive --tg-archive-channel channelname --tg-archive-new
```

Options:
- `--tg-archive`: Enable tg-archive integration
- `--tg-archive-channel`: Target channel username or ID to archive
- `--tg-archive-new` or `-n`: Create a new archive site (initial setup)
- `--tg-archive-sync` or `-s`: Sync messages to an existing archive
- `--tg-archive-path`: Output path for the archive (default: tg_archive)
- `--tg-archive-no-media`: Disable media downloads

### Proxy Rotation & VPN Integration
For improved anonymity and to bypass rate limiting or network restrictions:

```bash
python main.py --proxy --proxy-file proxies.txt --proxy-rotation-interval 10
```

Or with VPN:

```bash
python main.py --vpn ipvanish --vpn-username your_username --vpn-password your_password
```

Options:
- `--proxy`: Enable proxy rotation
- `--proxy-file`: Path to file containing proxy list (default: proxy.txt)
- `--proxy-rotation-interval`: Minutes between proxy rotations (default: 5)
- `--proxy-timeout`: Seconds for proxy validation timeout (default: 10)
- `--vpn`: VPN provider to use (choices: ipvanish, nordvpn)
- `--vpn-username`: VPN account username
- `--vpn-password`: VPN account password
- `--vpn-server`: Optional specific server to connect to

### Generating Visualizations
To generate network visualizations from the collected data:

```bash
python main.py --visualize --viz-type network --output-file network.html
```