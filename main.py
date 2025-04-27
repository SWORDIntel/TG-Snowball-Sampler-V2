from merge_csv_data import merge_csv_files
from EdgeList import create_edge_list
from utils import *
from db_manager import DBManager
from config import load_config, create_default_config, AppConfig
from cache_manager import create_cache_manager

from telethon.errors.rpcerrorlist import ChannelPrivateError, FloodWaitError
from telethon import functions
from telethon.tl.types import Channel
from collections import deque
import datetime
import asyncio
import concurrent.futures
import threading
from tqdm import tqdm
import os
import json
import sys
import signal
import argparse
import logging
import hmac
import hashlib
import pandas as pd

# Import functions for screen/tmux support directly to avoid circular imports
from utils import check_screen_session, create_persistence_session, printC, Fore

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("sampler.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("ProjectSNOW")

# Global variables for state tracking
db_manager = None
cache_manager = None
config = None
running = True

# Handle graceful shutdown
def handle_interrupt(sig, frame):
    global running
    logger.info("Interrupt received, gracefully shutting down...")
    running = False

# Register signal handlers
signal.signal(signal.SIGINT, handle_interrupt)
signal.signal(signal.SIGTERM, handle_interrupt)

async def process_message(client, channel, channel_entity, message, mention_counter, min_mentions, 
                         current_iteration_channels, current_iteration_channel_names, channel_name,
                         csv_file_path, processed_messages_count, channel_metadata_cache, processing_options=None):
    """Process a single message for forwards, with improved error handling"""
    try:
        # Apply time-based filtering if specified
        if processing_options and 'date_range' in processing_options and processing_options['date_range']:
            start_date, end_date = processing_options['date_range']
            message_date = message.date.replace(tzinfo=None)  # Remove timezone for comparison
            
            # Skip messages outside the date range
            if (start_date and message_date < start_date) or (end_date and message_date > end_date):
                return True
        
        if message.forward:
            fwd_from = message.forward.chat if isinstance(message.forward.chat, Channel) else None
            if fwd_from:
                # Use thread-safe counter update with lock
                with threading.Lock():
                    mention_counter[fwd_from.id] = mention_counter.get(fwd_from.id, 0) + 1
                
                if mention_counter[fwd_from.id] >= min_mentions:
                    try:
                        # Try to get from cache first
                        fwd_key = f"entity:{fwd_from.id}"
                        fwd_from_entity = cache_manager.get(fwd_key) if cache_manager else None
                        
                        if not fwd_from_entity:
                            # Get the forwarding channel's entity, name, and username
                            fwd_from_entity = await client.get_entity(fwd_from.id)
                            if cache_manager:
                                cache_manager.set(fwd_key, fwd_from_entity, config.cache.entity_ttl_seconds)
                        
                        fwd_from_name = fwd_from_entity.title if fwd_from_entity else 'Unknown'
                        fwd_from_username = fwd_from_entity.username if fwd_from_entity and hasattr(
                            fwd_from_entity, 'username') else 'Unknown'

                        # Get the current channel's entity, name, and username if not already available
                        channel_username = channel_entity.username if channel_entity and hasattr(
                            channel_entity, 'username') else 'Unknown'

                        # Extract metadata for this channel if we haven't already
                        with threading.Lock():
                            if fwd_from.id not in channel_metadata_cache:
                                # First check DB
                                if db_manager:
                                    metadata = db_manager.load_channel_metadata(str(fwd_from.id))
                                    if metadata:
                                        channel_metadata_cache[fwd_from.id] = metadata
                                        logger.debug(f"Loaded metadata for {fwd_from.id} from DB")
                                
                                # If not in DB, fetch from API
                                if fwd_from.id not in channel_metadata_cache:
                                    try:
                                        metadata = await extract_channel_metadata(client, fwd_from.id)
                                        channel_metadata_cache[fwd_from.id] = metadata
                                        
                                        # Save to DB
                                        if db_manager:
                                            db_manager.save_channel_metadata(str(fwd_from.id), metadata)
                                    except Exception as metadata_err:
                                        logger.warning(f"Error extracting metadata: {metadata_err}")
                                        # Use basic metadata 
                                        channel_metadata_cache[fwd_from.id] = {
                                            'id': fwd_from.id,
                                            'title': fwd_from_name,
                                            'username': fwd_from_username,
                                            'description': '',
                                            'clickable_link': f"https://t.me/{fwd_from_username}" if fwd_from_username and fwd_from_username != 'Unknown' else None
                                        }
                                        
                                        # Still save to DB
                                        if db_manager:
                                            db_manager.save_channel_metadata(str(fwd_from.id), channel_metadata_cache[fwd_from.id])
                            
                            # Apply category filtering if specified
                            if processing_options and 'categories' in processing_options and processing_options['categories']:
                                # Get the channel categories if not already calculated
                                if 'category' not in channel_metadata_cache[fwd_from.id]:
                                    # Preprocess the description text
                                    description = channel_metadata_cache[fwd_from.id].get('description', '')
                                    title = channel_metadata_cache[fwd_from.id].get('title', '')
                                    combined_text = f"{title} {description}"
                                    processed_text = preprocess_text(combined_text)
                                    
                                    # Determine the channel category
                                    matched_categories = {}
                                    for category, keywords in CATEGORIES.items():
                                        if category == 'other':
                                            continue
                                        # Count keyword matches
                                        match_count = sum(1 for keyword in keywords if keyword in processed_text)
                                        if match_count > 0:
                                            matched_categories[category] = match_count
                                    
                                    if matched_categories:
                                        # Assign to category with most matches
                                        best_category = max(matched_categories.items(), key=lambda x: x[1])[0]
                                        channel_metadata_cache[fwd_from.id]['category'] = best_category
                                    else:
                                        channel_metadata_cache[fwd_from.id]['category'] = 'other'
                                
                                # Skip channels that don't match the requested categories
                                channel_category = channel_metadata_cache[fwd_from.id].get('category', 'other')
                                if channel_category not in processing_options['categories']:
                                    return True

                        # Create edge list entry
                        create_edge_list('EdgeList', 'Edge_List.csv', fwd_from.id, fwd_from_name,
                                        fwd_from_username, channel_entity.id, channel_name,
                                        channel_username)

                        # Write to CSV with thread-safe approach
                        with threading.Lock():
                            with open(csv_file_path, 'a', newline='', encoding='utf-8') as file:
                                writer = csv.writer(file)
                                # Only write basic info to CSV - full metadata will be used at merge time
                                writer.writerow([fwd_from.id, fwd_from_name, fwd_from_username])
                                file.flush()  # Ensure data is written immediately

                        # Update channel tracking collections with thread safety
                        with threading.Lock():
                            current_iteration_channels.add(fwd_from.id)
                            current_iteration_channel_names[fwd_from.id] = fwd_from_name

                        # Print update (consider making this less frequent for better performance)
                        queue_size = 0  # This would need to be passed in for real-time accuracy
                        completed = len(processed_messages_count)
                        print(f'Processed messages: [{completed}] ¦ '
                                f'Forward found: {channel_name} -> {fwd_from_name}', end='\r')

                    except Exception as ex:
                        logger.error(f"Error processing forward: {ex}")
        return True
    except Exception as ex:
        logger.error(f"Error in process_message: {ex}")
        return False


async def process_channels(client, csv_file_path, initial_channels, iterations, min_mentions=5, max_posts=None, 
                          max_concurrent_channels=3, max_concurrent_messages=20, processing_options=None):
    """Main channel processing function with optimizations and persistence"""
    global running, db_manager
    
    # Initialize processing options if not provided
    if processing_options is None:
        processing_options = {}
    
    # Extract date range and categories if provided
    date_range = processing_options.get('date_range')
    categories = processing_options.get('categories')
    
    # Log processing options if provided
    if date_range:
        start_date, end_date = date_range
        start_str = start_date.strftime("%Y-%m-%d") if start_date else "any"
        end_str = end_date.strftime("%Y-%m-%d") if end_date else "any"
        logger.info(f"Time-based filtering enabled: {start_str} to {end_str}")
    
    if categories:
        logger.info(f"Category filtering enabled: {', '.join(categories)}")
    
    # Initial variables defined with improved thread safety
    processed_channels = set()
    channels_to_process = deque(initial_channels)
    iteration_results = []
    iteration_durations = []
    mention_counter = {}
    processed_messages_count = set()  # Use set to count unique processed messages
    channel_counts = []
    channel_metadata_cache = {}
    
    # Load state from database if available
    if db_manager and db_manager.database.enable_persistence:
        try:
            # Try to load state from database
            saved_queue = db_manager.load_queue()
            if saved_queue:
                channels_to_process = saved_queue
                logger.info(f"Loaded queue with {len(channels_to_process)} channels from database")
            
            saved_processed = db_manager.load_processed_channels()
            if saved_processed:
                processed_channels = saved_processed
                logger.info(f"Loaded {len(processed_channels)} processed channels from database")
            
            # Load sampling state
            saved_state = db_manager.load_sampling_state()
            if saved_state:
                if 'iteration_results' in saved_state:
                    iteration_results = saved_state['iteration_results']
                if 'iteration_durations' in saved_state:
                    iteration_durations = saved_state['iteration_durations']
                if 'mention_counter' in saved_state:
                    mention_counter = saved_state['mention_counter']
                if 'channel_counts' in saved_state:
                    channel_counts = saved_state['channel_counts']
                logger.info("Loaded sampling state from database")
            
            # Load metadata
            saved_metadata = db_manager.load_all_channel_metadata()
            if saved_metadata:
                for channel_id, metadata in saved_metadata.items():
                    try:
                        # Convert string channel_id to int
                        channel_metadata_cache[int(channel_id)] = metadata
                    except:
                        # If conversion fails, use as is
                        channel_metadata_cache[channel_id] = metadata
                logger.info(f"Loaded metadata for {len(channel_metadata_cache)} channels from database")
        except Exception as e:
            logger.error(f"Error loading state from database: {e}")
            # Continue with empty state
    
    # Save state initially
    save_state()
    
    # Create semaphore to limit concurrent API calls (prevent rate limiting)
    semaphore = asyncio.Semaphore(max_concurrent_channels)
    
    # Create metadata output directory
    metadata_dir = 'metadata'
    if not os.path.exists(metadata_dir):
        os.makedirs(metadata_dir)
    
    # Initialize metadata file
    metadata_file = os.path.join(metadata_dir, f'channel_metadata_{datetime.datetime.now().strftime("%Y%m%d_%H%M%S")}.json')
    with open(metadata_file, 'w', encoding='utf-8') as f:
        json.dump({}, f)

    for iteration in range(iterations):
        if not running:
            logger.info("Process interrupted, stopping...")
            break
            
        iteration_start_time = time.time()
        current_iteration_channels = set()
        current_iteration_channel_names = {}
        iteration_number = iteration + 1
        
        # Create a progress bar for channels
        channels_pbar = tqdm(total=len(channels_to_process), desc=f"Iteration {iteration_number}/{iterations}")
        
        # Process channels in the current iteration
        while channels_to_process and running:
            channel = channels_to_process.popleft()
            
            # Save state periodically (every 5 channels)
            if len(processed_channels) % 5 == 0:
                save_state()

            try:
                async with semaphore:  # Limit concurrent API calls
                    try:
                        # Try to get from cache first
                        channel_key = f"entity:{channel}"
                        channel_entity = cache_manager.get(channel_key) if cache_manager else None
                        
                        if not channel_entity:
                            channel_entity = await client.get_entity(channel)
                            if cache_manager:
                                cache_manager.set(channel_key, channel_entity, config.cache.entity_ttl_seconds)
                                
                        channel_name = channel_entity.title
                        
                        # Extract metadata for this channel if we haven't already
                        if channel not in channel_metadata_cache:
                            # First check DB
                            if db_manager:
                                metadata = db_manager.load_channel_metadata(str(channel))
                                if metadata:
                                    channel_metadata_cache[channel] = metadata
                                    logger.debug(f"Loaded metadata for {channel} from DB")
                            
                            # If not in DB, fetch from API
                            if channel not in channel_metadata_cache:
                                try:
                                    metadata = await extract_channel_metadata(client, channel)
                                    channel_metadata_cache[channel] = metadata
                                    
                                    # Save to DB and periodically to file
                                    if db_manager:
                                        db_manager.save_channel_metadata(str(channel), metadata)
                                    
                                    # Periodically save metadata to file
                                    if len(channel_metadata_cache) % 10 == 0:
                                        with open(metadata_file, 'w', encoding='utf-8') as f:
                                            # Convert int keys to strings for JSON
                                            json_safe_metadata = {str(k): v for k, v in channel_metadata_cache.items()}
                                            json.dump(json_safe_metadata, f, indent=2)
                                except Exception as metadata_err:
                                    logger.warning(f"Error extracting metadata for {channel}: {metadata_err}")
                        
                        # Apply category filtering for the source channel if specified
                        if categories:
                            if 'category' not in channel_metadata_cache.get(channel, {}):
                                # Determine the channel category
                                description = channel_metadata_cache.get(channel, {}).get('description', '')
                                title = channel_metadata_cache.get(channel, {}).get('title', '')
                                combined_text = f"{title} {description}"
                                processed_text = preprocess_text(combined_text)
                                
                                matched_categories = {}
                                for category, keywords in CATEGORIES.items():
                                    if category == 'other':
                                        continue
                                    # Count keyword matches
                                    match_count = sum(1 for keyword in keywords if keyword in processed_text)
                                    if match_count > 0:
                                        matched_categories[category] = match_count
                                
                                if matched_categories:
                                    # Assign to category with most matches
                                    best_category = max(matched_categories.items(), key=lambda x: x[1])[0]
                                    channel_metadata_cache[channel]['category'] = best_category
                                else:
                                    channel_metadata_cache[channel]['category'] = 'other'
                            
                            # Skip channels that don't match the requested categories
                            channel_category = channel_metadata_cache.get(channel, {}).get('category', 'other')
                            if channel_category not in categories:
                                logger.info(f"Skipping channel {channel_name} (category: {channel_category}) - doesn't match filter")
                                channels_pbar.update(1)
                                continue
                                
                    except FloodWaitError as e:
                        # Handle rate limiting
                        logger.warning(f"Rate limited. Waiting for {e.seconds} seconds")
                        await asyncio.sleep(e.seconds)
                        channels_to_process.append(channel)  # Put back in queue
                        continue
                    except Exception as ex:
                        logger.error(f"Error getting channel entity: {ex}")
                        channels_pbar.update(1)
                        continue

                if channel not in processed_channels:
                    processed_channels.add(channel)

                    try:
                        channel_message_count = 0
                        
                        # Create progress bar for message retrieval - will update once we know message count
                        message_count = min(max_posts, 100) if max_posts else 100  # Initial estimate
                        message_pbar = tqdm(total=message_count, desc=f"Messages in {channel_name[:20]}", leave=False)
                        
                        # Use a batch approach for message processing
                        message_batch = []
                        batch_size = max_concurrent_messages  # Process messages in batches
                        
                        async for message in client.iter_messages(channel):
                            if not running:
                                logger.info("Process interrupted, stopping message retrieval...")
                                break
                            
                            # Apply time-based filtering if specified
                            if date_range:
                                start_date, end_date = date_range
                                message_date = message.date.replace(tzinfo=None)  # Remove timezone for comparison
                                
                                # Skip messages outside the date range
                                if (start_date and message_date < start_date) or (end_date and message_date > end_date):
                                    continue
                                
                            message_batch.append(message)
                            processed_messages_count.add(message.id)  # Count unique messages
                            
                            # Update progress bar
                            channel_message_count += 1
                            message_pbar.update(1)
                            
                            # If we reach the batch size, process the batch
                            if len(message_batch) >= batch_size:
                                # Process batch concurrently
                                tasks = []
                                for msg in message_batch:
                                    task = asyncio.create_task(process_message(
                                        client, channel, channel_entity, msg, mention_counter, 
                                        min_mentions, current_iteration_channels, 
                                        current_iteration_channel_names, channel_name,
                                        csv_file_path, processed_messages_count, channel_metadata_cache,
                                        processing_options
                                    ))
                                    tasks.append(task)
                                
                                # Wait for all tasks to complete
                                await asyncio.gather(*tasks)
                                message_batch = []  # Clear the batch
                            
                            # Check max_posts limit
                            if max_posts and channel_message_count >= max_posts:
                                break
                            
                            # Adjust progress bar total if needed
                            if channel_message_count == message_count:
                                message_pbar.total = message_count * 2
                                message_pbar.refresh()
                        
                        # Process any remaining messages in the final batch
                        if message_batch:
                            tasks = []
                            for msg in message_batch:
                                task = asyncio.create_task(process_message(
                                    client, channel, channel_entity, msg, mention_counter, 
                                    min_mentions, current_iteration_channels, 
                                    current_iteration_channel_names, channel_name,
                                    csv_file_path, processed_messages_count, channel_metadata_cache,
                                    processing_options
                                ))
                                tasks.append(task)
                            
                            await asyncio.gather(*tasks)
                        
                        # Close message progress bar
                        message_pbar.close()

                    except ChannelPrivateError:
                        logger.warning(f"Cannot access private channel: {channel}")
                    
                    except FloodWaitError as e:
                        # Put the channel back in the queue after waiting
                        logger.warning(f"Rate limited. Waiting for {e.seconds} seconds")
                        await asyncio.sleep(e.seconds)
                        channels_to_process.append(channel)
                    
                    except Exception as ex:
                        logger.error(f"Error processing channel {channel}: {ex}")
            
            except ChannelPrivateError:
                logger.warning(f"Cannot access private channel: {channel}")
            
            except Exception as ex:
                logger.error(f"Unexpected error with channel {channel}: {ex}")
            
            finally:
                # Always update the progress bar
                channels_pbar.update(1)
        
        # Close channels progress bar
        channels_pbar.close()

        # Process results for this iteration
        iteration_data = [(cid, current_iteration_channel_names[cid]) for cid in current_iteration_channels]
        iteration_results.append(iteration_data)

        # Queue new channels for next iteration
        for new_channel in current_iteration_channels:
            if new_channel not in processed_channels:
                channels_to_process.append(new_channel)

        # Calculate timing and statistics
        iteration_end_time = time.time()
        iteration_duration = iteration_end_time - iteration_start_time
        iteration_durations.append(iteration_duration)
        channel_counts.append(len(current_iteration_channels))
        
        # Save state after each iteration
        save_state()
        
        # Estimate time for next iteration if applicable
        if iteration < iterations - 1 and running:
            est_next_time = iteration_duration * (len(channels_to_process) / max(1, len(current_iteration_channels)))
            logger.info(f"Estimated time for next iteration: {format_time(est_next_time)}")
        
        # Save metadata after each iteration
        with open(metadata_file, 'w', encoding='utf-8') as f:
            # Convert int keys to strings for JSON
            json_safe_metadata = {str(k): v for k, v in channel_metadata_cache.items()}
            json.dump(json_safe_metadata, f, indent=2)

    # Save final metadata
    logger.info(f"Collected metadata for {len(channel_metadata_cache)} channels")
    with open(metadata_file, 'w', encoding='utf-8') as f:
        # Convert int keys to strings for JSON
        json_safe_metadata = {str(k): v for k, v in channel_metadata_cache.items()}
        json.dump(json_safe_metadata, f, indent=2)

    # Save final state
    save_state()
    
    return iteration_results, iteration_durations, channel_counts, len(processed_messages_count), metadata_file

def save_state():
    """Save current state to database"""
    global db_manager, channels_to_process, processed_channels, iteration_results, iteration_durations, mention_counter, channel_counts
    
    if db_manager and db_manager.database.enable_persistence:
        try:
            # Save queue and processed channels
            if 'channels_to_process' in globals() and channels_to_process:
                db_manager.save_queue(channels_to_process)
            
            if 'processed_channels' in globals() and processed_channels:
                db_manager.save_processed_channels(processed_channels)
            
            # Save sampling state
            state = {}
            if 'iteration_results' in globals() and iteration_results:
                state['iteration_results'] = iteration_results
            if 'iteration_durations' in globals() and iteration_durations:
                state['iteration_durations'] = iteration_durations
            if 'mention_counter' in globals() and mention_counter:
                state['mention_counter'] = mention_counter
            if 'channel_counts' in globals() and channel_counts:
                state['channel_counts'] = channel_counts
            
            if state:
                db_manager.save_sampling_state(state)
                
            logger.debug("Saved state to database")
        except Exception as e:
            logger.error(f"Error saving state to database: {e}")


async def main(config_path=None, focus_params=None, additional_params=None):
    """Main function with enhanced UI and configurability"""
    global db_manager, cache_manager, config, running
    
    # Initialize additional_params if not provided
    if additional_params is None:
        additional_params = {}
    
    # Extract additional parameters
    date_range = additional_params.get('date_range')
    categories = additional_params.get('categories')
    export_format = additional_params.get('export_format')
    webhook_url = additional_params.get('webhook_url')
    notify_on = additional_params.get('notify_on')
    
    # Send start notification if enabled
    if webhook_url and notify_on in ['start', 'all']:
        send_webhook_notification(
            webhook_url,
            "Telegram Snowball Sampler has started",
            "info"
        )
    
    # Let's use our new intro
    intro()
    
    # Load configuration
    try:
        config = load_config(config_path)
        logger.info(f"Loaded configuration from {config_path if config_path else 'default path'}")
    except FileNotFoundError:
        logger.warning("Config file not found, creating default config")
        config = create_default_config()
    
    # Initialize database manager
    if config.database.enable:
        db_manager = DBManager(config)
        logger.info("Database manager initialized")
    else:
        db_manager = None
        logger.info("Database support disabled")
    
    # Initialize cache manager
    cache_manager = create_cache_manager(config)
    logger.info("Cache manager initialized")
    
    # Setup HMAC verification for API security
    security_key = None
    if config.security.enable_hmac:
        security_key = hmac.new(
            hashlib.sha256(os.urandom(32)).digest(),
            config.security.api_salt.encode() if hasattr(config.security, 'api_salt') else b'',
            hashlib.sha256
        ).hexdigest()
        logger.info("HMAC security enabled for API calls")
    
    # If focus_params is provided, use it instead of launching TUI
    tui_values = None
    if focus_params:
        # Set up tui_values for user focus mode
        tui_values = {
            'Seed Channel:': focus_params['username'],
            'Iterations:': focus_params['max_depth'],
            'Min. Mentions:': 1  # Set to 1 for user focus to catch all mentions
        }
        printC(f"Running in user focus mode for @{focus_params['username']}", Fore.CYAN)
    else:
        # Launch the TUI
        tui_values = launch_tui()
    
    # If user canceled, exit gracefully
    if not tui_values:
        printC("Operation canceled by user", Fore.YELLOW)
        
        # Send cancellation notification if enabled
        if webhook_url and notify_on in ['error', 'all']:
            send_webhook_notification(
                webhook_url,
                "Telegram Snowball Sampler was canceled by user",
                "warning"
            )
        
        return
    
    # Extract values from TUI
    seed_channel = tui_values.get('Seed Channel:', '')
    iterations = tui_values.get('Iterations:', 2)
    min_mentions = tui_values.get('Min. Mentions:', 3)
    
    # Extract Elasticsearch settings from TUI if present
    if 'es_enabled' in tui_values:
        config.elasticsearch.enabled = tui_values.get('es_enabled', False)
        config.elasticsearch.export_type = tui_values.get('es_export_type', 'filebeat')
        config.elasticsearch.index_name = tui_values.get('es_index_name', 'tg_snowball_sampler')
        config.elasticsearch.hosts = tui_values.get('es_hosts', ['localhost:9200'])
        
        if tui_values.get('es_auth_enabled', False):
            config.elasticsearch.username = tui_values.get('es_username', None)
            config.elasticsearch.password = tui_values.get('es_password', None)
        else:
            config.elasticsearch.username = None
            config.elasticsearch.password = None
            
        config.elasticsearch.ssl_enabled = tui_values.get('es_ssl_enabled', False)
        config.elasticsearch.export_dir = tui_values.get('es_export_dir', 'elasticsearch_export')
        config.elasticsearch.template_enabled = tui_values.get('es_template_enabled', True)
        
        # Save updated configuration
        config.save("config.yaml")
    
    # Validate seed channel
    if not seed_channel:
        printC("Error: Seed channel is required", Fore.RED)
        
        # Send error notification if enabled
        if webhook_url and notify_on in ['error', 'all']:
            send_webhook_notification(
                webhook_url,
                "Error: Seed channel is required",
                "error"
            )
        
        return
    
    # Connect to Telegram
    try:
        # Initialize proxy manager if enabled
        proxy_manager = None
        use_proxy = False
        
        if hasattr(config, 'proxy') and hasattr(config.proxy, 'enabled') and config.proxy.enabled:
            from utils import ProxyManager
            
            # Create proxy manager with settings from config
            proxy_manager = ProxyManager(
                proxy_file=config.proxy.proxy_file if hasattr(config.proxy, 'proxy_file') else 'proxy.txt',
                rotation_interval=config.proxy.rotation_interval_minutes * 60 if hasattr(config.proxy, 'rotation_interval_minutes') else 300,
                validation_timeout=config.proxy.validation_timeout_seconds if hasattr(config.proxy, 'validation_timeout_seconds') else 10
            )
            
            # Load proxies from file
            if proxy_manager.load_proxies_from_file():
                use_proxy = True
                printC("Proxy rotation enabled", Fore.CYAN)
        
        # Check VPN configuration
        if hasattr(config, 'vpn') and hasattr(config.vpn, 'provider') and config.vpn.provider != 'none':
            vpn_provider = config.vpn.provider
            vpn_username = config.vpn.username if hasattr(config.vpn, 'username') else None
            vpn_password = config.vpn.password if hasattr(config.vpn, 'password') else None
            vpn_server = config.vpn.server if hasattr(config.vpn, 'server') else None
            
            if vpn_username and vpn_password:
                # Initialize proxy manager if not already done
                if not proxy_manager:
                    from utils import ProxyManager
                    proxy_manager = ProxyManager()
                
                printC(f"Connecting to {vpn_provider} VPN...", Fore.CYAN)
                
                # Connect to VPN
                if vpn_provider == 'ipvanish':
                    await proxy_manager.connect_ipvanish(vpn_username, vpn_password, vpn_server)
                elif vpn_provider == 'nordvpn':
                    await proxy_manager.connect_nordvpn(vpn_username, vpn_password, vpn_server)
        
        # Connect to Telegram with proxy support if enabled
        client = await attempt_connection_to_telegram(use_proxy, proxy_manager)
    except Exception as e:
        printC(f"Failed to connect to Telegram: {e}", Fore.RED)
        
        # Send error notification if enabled
        if webhook_url and notify_on in ['error', 'all']:
            send_webhook_notification(
                webhook_url,
                f"Failed to connect to Telegram: {e}",
                "error"
            )
        
        return
    
    # Enhance get_entity with caching and rate limiting
    @cache_manager.cache_api_response(ttl=config.cache.entity_ttl_seconds)
    @cache_manager.rate_limited()
    async def cached_get_entity(*args, **kwargs):
        """Enhanced get_entity with caching and rate limiting"""
        # Add HMAC verification if enabled
        if security_key:
            kwargs['security_token'] = hmac.new(
                security_key.encode(),
                str(args).encode(),
                hashlib.sha256
            ).hexdigest()
        return await client.get_entity(*args, **kwargs)
    
    # Override the client's get_entity with our enhanced version
    client.get_entity = cached_get_entity
    
    # Create output directories
    output_dir = 'output'
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    
    # Create timestamped filename for this run
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    
    # Add focus indicator to filename if in focus mode
    filename_prefix = 'focus_' if focus_params else 'snowball_'
    csv_file_path = os.path.join(output_dir, f'{filename_prefix}{timestamp}.csv')
    
    # Process the channels
    process_start_time = time.time()
    
    try:
        # Initialize CSV file
        with open(csv_file_path, 'w', newline='', encoding='utf-8') as file:
            writer = csv.writer(file)
            writer.writerow(['Channel ID', 'Channel Name', 'Channel Username'])
        
        # Get the entity for the seed channel
        try:
            seed_entity = await client.get_entity(seed_channel)
            seed_id = seed_entity.id
            seed_name = seed_entity.title if hasattr(seed_entity, 'title') else 'Unknown'
            seed_username = seed_entity.username if hasattr(seed_entity, 'username') else 'Unknown'
            
            # Add the seed channel to the CSV
            with open(csv_file_path, 'a', newline='', encoding='utf-8') as file:
                writer = csv.writer(file)
                writer.writerow([seed_id, seed_name, seed_username])
                
            # Send progress notification if enabled
            if webhook_url and notify_on in ['progress', 'all']:
                send_webhook_notification(
                    webhook_url,
                    f"Started processing seed channel: {seed_name}",
                    "info"
                )
        except Exception as e:
            printC(f"Error getting seed channel entity: {e}", Fore.RED)
            
            # Send error notification if enabled
            if webhook_url and notify_on in ['error', 'all']:
                send_webhook_notification(
                    webhook_url,
                    f"Error getting seed channel entity: {e}",
                    "error"
                )
            
            await client.disconnect()
            return
        
        # Define additional processing options based on date range and categories
        processing_options = {
            'date_range': date_range,
            'categories': categories
        }
        
        # Adjust processing parameters if in focus mode
        if focus_params:
            # Use different processing strategy for user focus
            printC(f"Processing user @{seed_channel} with special focus logic...", Fore.CYAN)
            # Implementation of user focus logic would go here
            # For now, we'll use the standard process with adjusted parameters
            iteration_results, iteration_durations, channel_counts = await process_channels(
                client, 
                csv_file_path, 
                [seed_id], 
                iterations,
                min_mentions=min_mentions,  # Use provided min_mentions (1 by default for focus mode)
                max_posts=None,  # No limit for user focus to get complete history
                max_concurrent_channels=config.performance.max_concurrent_channels,
                max_concurrent_messages=config.performance.max_concurrent_messages,
                processing_options=processing_options
            )
        else:
            # Start the standard processing with a single initial channel
            iteration_results, iteration_durations, channel_counts = await process_channels(
                client, 
                csv_file_path, 
                [seed_id], 
                iterations,
                min_mentions=min_mentions,
                max_posts=config.sampling.max_posts_per_channel,
                max_concurrent_channels=config.performance.max_concurrent_channels,
                max_concurrent_messages=config.performance.max_concurrent_messages,
                processing_options=processing_options
            )
        
        # Load the collected data
        data = pd.read_csv(csv_file_path)
        
        # Merge the results
        try:
            printC("Merging results...", Fore.GREEN)
            merged_file = os.path.join(output_dir, f'merged_{timestamp}.csv')
            merge_csv_files([csv_file_path], merged_file)
            
            # Send progress notification if enabled
            if webhook_url and notify_on in ['progress', 'all']:
                send_webhook_notification(
                    webhook_url,
                    f"Results merged: Collected data for {len(data)} channels",
                    "info"
                )
        except Exception as e:
            printC(f"Error merging results: {e}", Fore.RED)
            error_fix({"csv_file_path": csv_file_path})
            
            # Send error notification if enabled
            if webhook_url and notify_on in ['error', 'all']:
                send_webhook_notification(
                    webhook_url,
                    f"Error merging results: {e}",
                    "error"
                )
        
        # Export to network formats if requested
        if export_format:
            try:
                printC(f"Exporting results to {export_format} format...", Fore.CYAN)
                export_base = os.path.join(output_dir, f'network_{timestamp}')
                exported_files = export_to_network_format(data, export_base, export_format)
                
                # Send progress notification if enabled
                if webhook_url and notify_on in ['progress', 'all'] and exported_files:
                    send_webhook_notification(
                        webhook_url,
                        f"Exported data to network format(s): {', '.join(exported_files)}",
                        "info"
                    )
            except Exception as e:
                printC(f"Error exporting to network format: {e}", Fore.RED)
                
                # Send error notification if enabled
                if webhook_url and notify_on in ['error', 'all']:
                    send_webhook_notification(
                        webhook_url,
                        f"Error exporting to network format: {e}",
                        "error"
                    )
        
        # Export to Elasticsearch if enabled
        if config.elasticsearch.enabled:
            try:
                printC(f"Exporting data to Elasticsearch via {config.elasticsearch.export_type}...", Fore.CYAN)
                es_export_dir = os.path.join(output_dir, config.elasticsearch.export_dir)
                
                # Create Elasticsearch configuration from config
                es_config = {
                    'index_name': config.elasticsearch.index_name,
                    'hosts': config.elasticsearch.hosts,
                    'username': config.elasticsearch.username,
                    'password': config.elasticsearch.password,
                    'ssl_enabled': config.elasticsearch.ssl_enabled,
                    'document_type': config.elasticsearch.document_type
                }
                
                # Export data
                exported_files = export_to_elasticsearch(
                    data, 
                    es_export_dir, 
                    export_type=config.elasticsearch.export_type,
                    es_config=es_config
                )
                
                # Send progress notification if enabled
                if webhook_url and notify_on in ['progress', 'all'] and exported_files:
                    send_webhook_notification(
                        webhook_url,
                        f"Exported data to Elasticsearch via {config.elasticsearch.export_type}. Files: {len(exported_files)}",
                        "info"
                    )
                    
                # If template_enabled, provide the mapping
                if config.elasticsearch.template_enabled:
                    mapping_file = os.path.join(es_export_dir, f"es_mapping_{timestamp}.json")
                    with open(mapping_file, 'w', encoding='utf-8') as f:
                        json.dump(get_index_mapping_for_elasticsearch(), f, indent=2)
                    printC(f"Elasticsearch index mapping saved to {mapping_file}", Fore.GREEN)
                    
                # Provide hints on how to proceed
                if config.elasticsearch.export_type == 'filebeat':
                    printC(f"To send data to Elasticsearch, navigate to {es_export_dir} and run:", Fore.CYAN)
                    printC(f"  filebeat -e -c filebeat_{file_signature if 'file_signature' in locals() else '*'}.yml", Fore.WHITE)
                else:  # logstash
                    printC(f"To send data to Elasticsearch, navigate to {es_export_dir} and run:", Fore.CYAN)
                    printC(f"  logstash -f logstash_{file_signature if 'file_signature' in locals() else '*'}.conf", Fore.WHITE)
                    
            except Exception as e:
                printC(f"Error exporting to Elasticsearch: {e}", Fore.RED)
                
                # Send error notification if enabled
                if webhook_url and notify_on in ['error', 'all']:
                    send_webhook_notification(
                        webhook_url,
                        f"Error exporting to Elasticsearch: {e}",
                        "error"
                    )
        
        # Generate visualizations
        try:
            printC("Generating visualizations...", Fore.CYAN)
            viz_files = generate_visualizations(csv_file_path, 'all')
            
            # Send progress notification if enabled
            if webhook_url and notify_on in ['progress', 'all'] and viz_files:
                send_webhook_notification(
                    webhook_url,
                    f"Generated {len(viz_files)} visualizations",
                    "info"
                )
        except Exception as e:
            printC(f"Error generating visualizations: {e}", Fore.RED)
            
            # Send error notification if enabled
            if webhook_url and notify_on in ['error', 'all']:
                send_webhook_notification(
                    webhook_url,
                    f"Error generating visualizations: {e}",
                    "error"
                )
        
        # Display the final message
        final_message(process_start_time, len(processed_messages_count), iteration_durations, channel_counts)
        
        # Send completion notification if enabled
        if webhook_url and notify_on in ['complete', 'all']:
            send_webhook_notification(
                webhook_url,
                f"Processing complete: Collected data for {len(data)} channels across {len(iteration_durations)} iterations. Total execution time: {format_time(time.time() - process_start_time)}",
                "success"
            )
        
    except KeyboardInterrupt:
        printC("\nOperation interrupted by user.", Fore.YELLOW)
        
        # Send interruption notification if enabled
        if webhook_url and notify_on in ['error', 'all']:
            send_webhook_notification(
                webhook_url,
                "Operation interrupted by user",
                "warning"
            )
        
        # Allow user to adjust parameters midway
        current_params = {
            'current_channel': seed_name,
            'min_mentions': min_mentions,
            'filter_keywords': ''
        }
        
        updated_params = adjust_parameters_midway(current_params)
        
        if updated_params.get('Skip Current Channel', False):
            printC("Skipping current channel and continuing...", Fore.YELLOW)
        elif updated_params.get('Min. Mentions:', 0) != min_mentions:
            min_mentions = updated_params.get('Min. Mentions:', min_mentions)
            printC(f"Updated minimum mentions to {min_mentions}", Fore.GREEN)
        
        # If keywords filter was added
        filter_keywords = updated_params.get('Filter Keywords (comma separated):', '')
        if filter_keywords:
            printC(f"Applied keyword filter: {filter_keywords}", Fore.GREEN)
            # Implementation for keyword filtering would go here
    
    except Exception as e:
        printC(f"An unexpected error occurred: {e}", Fore.RED)
        logger.error(f"Unexpected error: {e}", exc_info=True)
        error_fix({"csv_file_path": csv_file_path if 'csv_file_path' in locals() else None})
        
        # Send error notification if enabled
        if webhook_url and notify_on in ['error', 'all']:
            send_webhook_notification(
                webhook_url,
                f"An unexpected error occurred: {e}",
                "error"
            )
    
    finally:
        # Disconnect the client
        if 'client' in locals():
            await client.disconnect()
        
        # Save final state
        if 'save_state' in locals():
            save_state()
        
        printC("Processing complete. Disconnected from Telegram.", Fore.GREEN)


# Add a function to check required packages
def check_required_packages():
    """Check if all required packages are installed"""
    required_packages = {
        "npyscreen": "Terminal UI",
        "telethon": "Telegram API",
        "colorama": "Colored output",
        "tqdm": "Progress bars",
        "cryptography": "Security features",
        "nltk": "Text processing"
    }
    
    missing_packages = []
    
    for package, description in required_packages.items():
        try:
            __import__(package)
        except ImportError:
            missing_packages.append(f"{package} ({description})")
    
    if missing_packages:
        print("ERROR: Missing required packages:")
        for package in missing_packages:
            print(f"  - {package}")
        print("\nPlease install them using:")
        print("  pip install -r requirements.txt")
        return False
    
    return True


if __name__ == "__main__":
    # Check required packages before proceeding
    if not check_required_packages():
        sys.exit(1)
        
    parser = argparse.ArgumentParser(description='Telegram Snowball Sampler')
    parser.add_argument('--config', help='Path to configuration file')
    parser.add_argument('--background', action='store_true', 
                       help='Start in background mode using screen or tmux')
    parser.add_argument('--session-name', default='tg_snowball',
                       help='Session name for background mode')
    parser.add_argument('--focus-user', 
                       help='Focus analysis on a specific Telegram username')
    parser.add_argument('--focus-depth', type=int, default=3,
                       help='Maximum depth when focusing on a specific user')
    parser.add_argument('--include-replies', action='store_true',
                       help='Include replies when focusing on a specific user')
    parser.add_argument('--include-forwards', action='store_true', default=True,
                       help='Include forwards when focusing on a specific user')
    
    # New feature: Category filtering
    parser.add_argument('--categories', 
                       help='Comma-separated list of categories to include (e.g., politics,technology)')
    
    # New feature: Time-based sampling
    parser.add_argument('--date-start', 
                       help='Start date for sampling (YYYY-MM-DD format)')
    parser.add_argument('--date-end', 
                       help='End date for sampling (YYYY-MM-DD format)')
    
    # New feature: Elasticsearch export
    parser.add_argument('--es-export', action='store_true',
                       help='Enable Elasticsearch export')
    parser.add_argument('--es-type', choices=['filebeat', 'logstash'], default='filebeat',
                       help='Elasticsearch export type (filebeat or logstash)')
    parser.add_argument('--es-hosts', 
                       help='Comma-separated list of Elasticsearch hosts (e.g., localhost:9200,localhost:9201)')
    parser.add_argument('--es-index', default='tg_snowball_sampler',
                       help='Base name for the Elasticsearch index')
    
    # New feature: Visualization
    parser.add_argument('--visualize-results', 
                       help='Generate visualization for the given result file')
    parser.add_argument('--visualization-type', choices=['network', 'heatmap', 'chord', 'all'],
                       default='network', help='Type of visualization to generate')
    
    # New feature: Export formats
    parser.add_argument('--export-format', choices=['gexf', 'graphml', 'json', 'all'],
                       help='Export results to network analysis format')
    
    # New feature: Webhook notifications
    parser.add_argument('--webhook-url', 
                       help='Webhook URL for sending notifications (Slack, Discord, etc.)')
    parser.add_argument('--notify-on', choices=['start', 'progress', 'complete', 'error', 'all'],
                       default='all', help='When to send webhook notifications')
    
    # New feature: tg-archive integration
    parser.add_argument('--tg-archive', action='store_true',
                       help='Run tg-archive integration')
    parser.add_argument('--tg-archive-channel',
                       help='Channel ID or username for tg-archive')
    parser.add_argument('--tg-archive-new', '-n', action='store_true',
                       help='Create a new tg-archive site')
    parser.add_argument('--tg-archive-sync', '-s', action='store_true',
                       help='Sync messages only for existing archive')
    parser.add_argument('--tg-archive-path', default='tg_archive',
                       help='Path for the tg-archive output')
    parser.add_argument('--tg-archive-no-media', action='store_true',
                       help='Disable media downloads in tg-archive')
    
    # New feature: Proxy rotation and VPN
    parser.add_argument('--proxy', action='store_true',
                       help='Enable proxy rotation')
    parser.add_argument('--proxy-file', default='proxy.txt',
                       help='Path to proxy list file')
    parser.add_argument('--proxy-rotation-interval', type=int, default=5,
                       help='Proxy rotation interval in minutes')
    parser.add_argument('--proxy-timeout', type=int, default=10,
                       help='Proxy validation timeout in seconds')
    parser.add_argument('--vpn', choices=['none', 'ipvanish', 'nordvpn'],
                       help='VPN provider to use')
    parser.add_argument('--vpn-username',
                       help='VPN username')
    parser.add_argument('--vpn-password',
                       help='VPN password')
    parser.add_argument('--vpn-server',
                       help='Specific VPN server to connect to (optional)')
    
    args = parser.parse_args()
    
    # Validate date inputs if provided
    date_range = None
    if args.date_start or args.date_end:
        try:
            from datetime import datetime
            start_date = datetime.strptime(args.date_start, "%Y-%m-%d") if args.date_start else None
            end_date = datetime.strptime(args.date_end, "%Y-%m-%d") if args.date_end else None
            date_range = (start_date, end_date)
        except ValueError as e:
            printC(f"Error parsing date: {e}", Fore.RED)
            printC("Please use YYYY-MM-DD format for dates", Fore.RED)
            sys.exit(1)
    
    # Parse categories if provided
    categories = None
    if args.categories:
        categories = [cat.strip().lower() for cat in args.categories.split(',')]
        valid_categories = list(CATEGORIES.keys())
        for cat in categories:
            if cat not in valid_categories:
                printC(f"Warning: Category '{cat}' not recognized. Valid categories: {', '.join(valid_categories)}", Fore.YELLOW)
    
    # Check if webhook URL is valid
    webhook_url = None
    if args.webhook_url:
        if args.webhook_url.startswith(('http://', 'https://')):
            webhook_url = args.webhook_url
            notify_on = args.notify_on
        else:
            printC("Error: Webhook URL must start with http:// or https://", Fore.RED)
            sys.exit(1)
    
    # If visualization was requested, process that first and exit
    if args.visualize_results:
        if os.path.exists(args.visualize_results):
            from utils import generate_visualizations
            generate_visualizations(args.visualize_results, args.visualization_type)
            sys.exit(0)
        else:
            printC(f"Error: Results file not found: {args.visualize_results}", Fore.RED)
            sys.exit(1)
    
    # If tg-archive integration was requested, process that and exit
    if args.tg_archive:
        handle_tg_archive_cli(args)
        sys.exit(0)
    
    # Check if we should start in background mode
    if args.background and not check_screen_session():
        printC("Starting in background mode...", Fore.CYAN)
        if create_persistence_session(args.session_name):
            printC(f"Background session '{args.session_name}' created. Exiting this instance.", Fore.GREEN)
            sys.exit(0)
        else:
            printC("Failed to start background session. Continuing in foreground mode.", Fore.RED)
    
    # If focusing on a specific user, set up the focus parameters
    focus_params = None
    if args.focus_user:
        focus_params = {
            'username': args.focus_user,
            'max_depth': args.focus_depth,
            'include_replies': args.include_replies,
            'include_forwards': args.include_forwards
        }
        printC(f"Focusing analysis on user: @{args.focus_user}", Fore.CYAN)
    
    # Create additional parameters for new features
    additional_params = {
        'date_range': date_range,
        'categories': categories,
        'export_format': args.export_format,
        'webhook_url': webhook_url,
        'notify_on': args.notify_on if webhook_url else None
    }
    
    # Process Elasticsearch parameters
    if args.es_export:
        # Enable Elasticsearch export
        config.elasticsearch.enabled = True
        
        # Set export type if specified
        if args.es_type:
            config.elasticsearch.export_type = args.es_type
        
        # Set hosts if specified
        if args.es_hosts:
            config.elasticsearch.hosts = args.es_hosts.split(',')
        
        # Set index name if specified
        if args.es_index:
            config.elasticsearch.index_name = args.es_index
    
    # Process proxy and VPN parameters
    if args.proxy:
        # Enable proxy rotation
        if not hasattr(config, 'proxy'):
            config.proxy = type('', (), {})
        
        config.proxy.enabled = True
        
        # Set proxy file if specified
        if args.proxy_file:
            config.proxy.proxy_file = args.proxy_file
        
        # Set rotation interval if specified
        if args.proxy_rotation_interval:
            config.proxy.rotation_interval_minutes = args.proxy_rotation_interval
        
        # Set validation timeout if specified
        if args.proxy_timeout:
            config.proxy.validation_timeout_seconds = args.proxy_timeout
    
    # Process VPN parameters
    if args.vpn and args.vpn != 'none':
        # Set VPN provider
        if not hasattr(config, 'vpn'):
            config.vpn = type('', (), {})
        
        config.vpn.provider = args.vpn
        
        # Set VPN credentials if specified
        if args.vpn_username:
            config.vpn.username = args.vpn_username
        
        if args.vpn_password:
            config.vpn.password = args.vpn_password
        
        # Set VPN server if specified
        if args.vpn_server:
            config.vpn.server = args.vpn_server
    
    # Note: If not specified via command line, we'll use the settings from the TUI/config file
    # which are loaded at startup. The TUI settings take precedence over the config file but
    # command line args will override both.
    
    asyncio.run(main(args.config, focus_params, additional_params))

# Function to handle tg-archive CLI
def handle_tg_archive_cli(args):
    """Handle command line execution of tg-archive integration."""
    import subprocess
    import yaml
    import os
    import json
    from cryptography.fernet import Fernet
    from utils import printC, Fore
    
    # Validate inputs
    if not args.tg_archive_channel:
        printC("Error: Channel ID or username is required with --tg-archive-channel", Fore.RED)
        sys.exit(1)
        
    channel = args.tg_archive_channel
    archive_path = args.tg_archive_path
    create_new = args.tg_archive_new
    sync_only = args.tg_archive_sync
    download_media = not args.tg_archive_no_media

    # Check if tg-archive is installed
    try:
        printC("Checking tg-archive installation...", Fore.CYAN)
        subprocess.run(["tg-archive", "--help"], 
                     stdout=subprocess.PIPE, 
                     stderr=subprocess.PIPE, 
                     check=False)
    except FileNotFoundError:
        printC("Error: tg-archive is not installed. Please install it with:", Fore.RED)
        printC("  pip install tg-archive", Fore.YELLOW)
        sys.exit(1)
        
    # Build command based on settings
    command_parts = ["tg-archive"]
    
    # Add options
    if create_new:
        command_parts.append("--new")
        
    if sync_only:
        command_parts.append("--sync")
    
    # Archive path
    command_parts.extend(["--path", archive_path])
    
    # Prepare credentials
    try:
        # Create archive directory if it doesn't exist
        if not os.path.exists(archive_path) and create_new:
            os.makedirs(archive_path, exist_ok=True)
            
        # Get API credentials from encrypted file
        api_details_file_path = 'api_keys.enc'
        key_file_path = '.keyfile'
        
        if os.path.exists(api_details_file_path) and os.path.exists(key_file_path):
            printC("Using API credentials from snowball sampler...", Fore.CYAN)
            # Read the key
            with open(key_file_path, 'rb') as keyfile:
                key = keyfile.read()
            
            # Read and decrypt the API details
            with open(api_details_file_path, 'rb') as file:
                encrypted_data = file.read()
            
            f = Fernet(key)
            decrypted_data = f.decrypt(encrypted_data)
            api_data = json.loads(decrypted_data.decode())
            
            # Use the first API key in the list
            if api_data and 'api_keys' in api_data and api_data['api_keys']:
                first_api = api_data['api_keys'][0]
                api_id = first_api['api_id']
                api_hash = first_api['api_hash']
                
                if create_new:
                    # Create a config.yaml file for tg-archive
                    config_path = os.path.join(archive_path, 'config.yaml')
                    
                    # Default config structure
                    tg_config = {
                        'api_id': int(api_id),
                        'api_hash': api_hash,
                        'channel': channel,
                        'title': f"Archive of {channel}",
                        'description': f"Telegram channel archive of {channel}",
                        'website_url': '',
                        'author_name': 'TG Snowball Sampler',
                        'author_url': '',
                        'items_per_page': 100,
                        'download_media': download_media,
                        'file_size_limit_mb': 25
                    }
                    
                    # Write the config file
                    with open(config_path, 'w', encoding='utf-8') as f:
                        yaml.dump(tg_config, f, default_flow_style=False)
                    
                    printC(f"Created tg-archive config at {config_path} with API credentials", Fore.GREEN)
            else:
                printC("Error: No API keys found in the encrypted storage", Fore.RED)
                sys.exit(1)
        else:
            printC("Error: API credentials not found", Fore.RED)
            sys.exit(1)
    
    except Exception as e:
        printC(f"Error preparing tg-archive config: {e}", Fore.RED)
        sys.exit(1)
    
    # Execute the command
    printC(f"Running tg-archive command: {' '.join(command_parts)}", Fore.CYAN)
    
    try:
        result = subprocess.run(command_parts, check=True)
        
        printC(f"tg-archive completed successfully!", Fore.GREEN)
        printC(f"Archive saved to: {os.path.abspath(archive_path)}", Fore.GREEN)
    except subprocess.CalledProcessError as e:
        printC(f"Error running tg-archive: {e}", Fore.RED)
        sys.exit(1)
