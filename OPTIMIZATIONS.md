# Telegram Snowball Sampler Optimizations

This document details the optimizations and security enhancements made to the codebase.

## Secure API Key Management

The API key storage system was completely overhauled to implement:

- **Encryption**: API keys are now stored in an encrypted file rather than plaintext, using Fernet symmetric encryption
- **Device-Binding**: The encryption key is derived using device-specific information, making the encrypted API keys unusable if copied to another device
- **Multiple API Keys**: The system now supports storing and using multiple Telegram API keys
- **Automatic Rotation**: When one API key hits rate limits, the system automatically tries alternative keys
- **Usage Statistics**: The system tracks usage counts and timestamps to distribute load across keys
- **Automatic Fallback**: If all API keys fail, the system prompts for a new key

## Performance Optimizations

### Concurrent Processing

- **Semaphore-Limited Concurrency**: Prevents hitting API rate limits by controlling the number of simultaneous requests
- **Batch Processing**: Messages are processed in batches rather than individually
- **Parallel Tasks**: Uses `asyncio.gather()` to process message batches concurrently
- **Thread-Safe Data Structures**: Added locks around shared data structures to ensure thread safety

### Progress Tracking & User Experience

- **Progress Bars**: Added tqdm progress bars for:
  - Overall process
  - Each iteration
  - Channel processing
  - Message retrieval
- **Time Estimation**: Added estimation of remaining time for iterations
- **Terminal UI**: Implemented a proper TUI using npyscreen for configuration
- **Improved Error Handling**: Better error messages and recovery mechanisms
- **Rate Limit Handling**: Automatically detects and waits for rate limit timeouts

### CSV Processing Improvements

- **Parallel CSV Processing**: Uses ThreadPoolExecutor for concurrent processing of CSV data
- **Memory-Efficient Hashing**: Uses MD5 hashing of rows to efficiently detect duplicates
- **Chunked Processing**: Breaks large datasets into manageable chunks
- **Backup Mechanisms**: Automatically creates backups if primary file writing fails

## Error Handling Improvements

- **Comprehensive Error Catching**: Each component has proper exception handling
- **Graceful Degradation**: The system attempts to continue operation when possible
- **Rate Limit Recovery**: Automatically handles Telegram API rate limits
- **Keyboard Interrupt Handling**: Properly saves partial results if the user terminates the process
- **Detailed Error Messages**: More informative error output with full stack traces in critical failures

## Security Enhancements

- **HMAC Authentication**: Used for device binding
- **Secure Key Derivation**: Implements PBKDF2 for key derivation
- **Encrypted Storage**: All sensitive data is encrypted at rest
- **Minimal Privileges**: Code follows principle of least privilege

## Usage Tips

1. **API Key Management**:
   - Add multiple API keys for better performance
   - The system will automatically rotate between them

2. **Optimal Performance Settings**:
   - Set iterations to 3 for most use cases
   - Set min_mentions to 5 to filter out noise
   - Set max_posts to 1000 for a good balance of depth vs. speed

3. **Recovery**:
   - If the process is interrupted, results are still saved
   - The merge functionality will combine results from multiple runs

## Additional Implementations from TODOs

- [x] Added per-find CSV/TXT file saves to prevent loss of data if execution is stopped early
- [x] Added progress bars and detailed feedback
- [x] Added time remaining estimation
- [x] Added multi-API parallel processing
- [x] Improved edgelist creation
- [x] Enhanced CSV merging 
- [x] Added channel categorization
- [x] Implemented clickable links in HTML output

## Channel Categorization and Organization

The codebase now includes a sophisticated channel categorization system:

- **Automatic Content Classification**: Channels are automatically categorized based on their content using:
  - Rule-based classification with predefined keywords for categories
  - Machine learning clustering for channels that don't match predefined categories
  - Text preprocessing with stopword removal and TF-IDF vectorization

- **Category-Based Organization**: Channels are organized into folders by category:
  - Politics
  - News
  - Technology
  - Cybersecurity
  - Cryptocurrency
  - Entertainment
  - Business
  - Science
  - Health
  - Sports
  - Education
  - Travel
  - Military
  - Religion
  - Other/Uncategorized
  - Automatically discovered clusters

- **Metadata Collection**: Rich metadata is collected for each channel:
  - Channel description
  - Member count (when available)
  - Creation date
  - Verification status
  - Channel history and statistics

## Enhanced Output and Visualization

- **HTML Index with Clickable Links**: 
  - Main index page showing all categories
  - Category-specific pages with channel listings
  - Direct clickable links to Telegram channels
  - Mobile-responsive design for easy browsing
  - Visual indicators for channel statistics

- **Improved Data Organization**:
  - Category-specific CSV files
  - JSON metadata export
  - Comprehensive channel index
  - Deduplication across categories
  - Persistent metadata storage

## Usage Example

After running the snowball sampler, you'll find:

1. A `merged` folder containing:
   - `merged_channels.csv`: All channels in a single file
   - `index.html`: Main category index with visual navigation
   - `categorized/`: Folder with category-specific subfolders
   - `category_index.json`: Metadata about all categories

2. Each category folder (e.g., `categorized/cybersecurity/`) contains:
   - `channels.csv`: CSV file with channels in this category
   - `channels.html`: HTML page with clickable links to these channels

3. Open `merged/index.html` in any web browser to explore the categorized channels with clickable links.

These enhancements make the data much more navigable and useful for research purposes, allowing for easy exploration of the Telegram channel network by topic area. 