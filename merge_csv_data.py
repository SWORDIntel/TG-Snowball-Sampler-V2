import os
import pandas as pd
import csv
from tqdm import tqdm
import hashlib
import concurrent.futures
from utils import printC, classify_channels, create_clickable_links
from colorama import Fore
import json
import shutil

def merge_csv_files(results_folder, merged_folder, merged_filename, main_directory_csv):
    printC('Merging and de-duplicating CSVs...', Fore.CYAN)
    merged_file_path = os.path.join(merged_folder, merged_filename)

    # Create 'merged' directory if it doesn't exist
    if not os.path.exists(merged_folder):
        os.makedirs(merged_folder)

    # Check for CSV files in the results folder
    csv_files = [f for f in os.listdir(results_folder) if f.endswith('.csv')]
    if not csv_files:
        printC(f"No CSV files found in {results_folder}", Fore.YELLOW)
        return

    # Calculate total rows to process for progress bar
    total_rows = 0
    for file in csv_files:
        try:
            file_path = os.path.join(results_folder, file)
            with open(file_path, 'r', newline='', encoding='utf-8') as csvfile:
                total_rows += sum(1 for _ in csvfile) - 1  # Subtract 1 for header
        except Exception as e:
            printC(f"Error counting rows in {file}: {e}", Fore.RED)

    # Read existing data from the merged file or create a new DataFrame
    try:
        if os.path.exists(merged_file_path):
            existing_data = pd.read_csv(merged_file_path)
            printC(f"Found existing merged data with {len(existing_data)} records", Fore.GREEN)
        else:
            existing_data = pd.DataFrame(columns=['Channel ID', 'Channel Name', 'Channel Username', 'Category', 'Link'])
            printC("Creating new merged data file", Fore.GREEN)
    except Exception as e:
        printC(f"Error reading existing merged data: {e}", Fore.RED)
        existing_data = pd.DataFrame(columns=['Channel ID', 'Channel Name', 'Channel Username', 'Category', 'Link'])

    # Use a hash set for efficient duplicate checking
    # Hash the entire row to handle potential duplicates with different column ordering
    existing_hashes = set()
    for _, row in existing_data.iterrows():
        # Create a hash of the row values using only the identification columns
        row_id_values = [str(row['Channel ID']), str(row['Channel Name']), str(row['Channel Username'])]
        row_hash = hashlib.md5('|'.join(row_id_values).encode()).hexdigest()
        existing_hashes.add(row_hash)

    # Process all CSV files and collect new unique rows
    all_data = []
    with tqdm(total=total_rows, desc="Processing rows") as pbar:
        for file in tqdm(csv_files, desc="Processing files", leave=False):
            file_path = os.path.join(results_folder, file)
            try:
                with open(file_path, 'r', newline='', encoding='utf-8') as csvfile:
                    reader = csv.reader(csvfile)
                    header = next(reader)  # Skip header row
                    
                    for row in reader:
                        if not row:  # Skip empty rows
                            continue
                            
                        # Create a hash of the row values
                        row_hash = hashlib.md5('|'.join([str(val) for val in row[:3]]).encode()).hexdigest()
                        
                        # Add row if it's not already in the existing data
                        if row_hash not in existing_hashes:
                            # Create a full row with default category and link
                            full_row = row.copy()
                            # If the file has fewer columns than expected, pad with defaults
                            while len(full_row) < 3:
                                full_row.append('')
                            # Add default category and link if not present
                            if len(full_row) == 3:
                                full_row.extend(['', ''])  # Category and Link placeholders
                            
                            all_data.append(full_row)
                            existing_hashes.add(row_hash)
                        
                        pbar.update(1)
            except Exception as e:
                printC(f"Error processing file {file}: {e}", Fore.RED)
                continue

    # No new data to process
    if not all_data:
        printC("No new data to add to the merged file", Fore.YELLOW)
        return

    # Create new dataframe with the collected data
    columns = ['Channel ID', 'Channel Name', 'Channel Username', 'Category', 'Link']
    new_data = pd.DataFrame(all_data, columns=columns[:len(all_data[0])])
    
    # Prepare metadata for classification
    channels_metadata = []
    for _, row in new_data.iterrows():
        channel_metadata = {
            'id': row['Channel ID'],
            'title': row['Channel Name'],
            'username': row['Channel Username'] if pd.notna(row['Channel Username']) else None,
            'description': ''  # We don't have descriptions in the CSV data
        }
        channels_metadata.append(channel_metadata)
    
    # Add clickable links
    clickable_links = create_clickable_links(channels_metadata)
    for i, row in new_data.iterrows():
        channel_id = row['Channel ID']
        if channel_id in clickable_links and clickable_links[channel_id]:
            new_data.at[i, 'Link'] = clickable_links[channel_id]
    
    # Classify channels
    printC("Classifying channels...", Fore.CYAN)
    channel_categories = classify_channels(channels_metadata)
    for i, row in new_data.iterrows():
        channel_id = row['Channel ID']
        if channel_id in channel_categories:
            new_data.at[i, 'Category'] = channel_categories[channel_id]
    
    # Add new data to existing data
    combined_data = pd.concat([existing_data, new_data])
    
    # Remove duplicates based on Channel ID, keeping the first occurrence (which may have category and link)
    combined_data.drop_duplicates(subset=['Channel ID'], keep='first', inplace=True)
    combined_data.reset_index(drop=True, inplace=True)
    
    # Write merged data to CSV file
    try:
        combined_data.to_csv(merged_file_path, index=False, encoding='utf-8')
        printC(f"Merged data written to {merged_file_path}: {len(combined_data)} total records (+{len(new_data)} new)", Fore.GREEN)
    except Exception as e:
        printC(f"Error writing merged data: {e}", Fore.RED)
        # Backup plan if writing fails
        backup_path = os.path.join(merged_folder, f"backup_{merged_filename}")
        try:
            combined_data.to_csv(backup_path, index=False, encoding='utf-8')
            printC(f"Backup data written to {backup_path}", Fore.YELLOW)
        except Exception as backup_error:
            printC(f"Failed to write backup file as well: {backup_error}. Data may be lost.", Fore.RED)
            return
    
    # Create categorized folders
    categorized_folder = os.path.join(merged_folder, 'categorized')
    if not os.path.exists(categorized_folder):
        os.makedirs(categorized_folder)
    
    # Create a category index file that lists all categories
    category_index = {'categories': []}
    
    # Write channels to category-specific files
    for category in combined_data['Category'].unique():
        if pd.isna(category) or category == '':
            category = 'other'
        
        # Create category folder
        category_path = os.path.join(categorized_folder, category)
        if not os.path.exists(category_path):
            os.makedirs(category_path)
        
        # Filter data for this category
        category_data = combined_data[combined_data['Category'] == category]
        
        # Write to CSV
        category_file_path = os.path.join(category_path, 'channels.csv')
        category_data.to_csv(category_file_path, index=False, encoding='utf-8')
        
        # Create HTML file with clickable links
        html_file_path = os.path.join(category_path, 'channels.html')
        create_html_file(category_data, html_file_path, category)
        
        # Add to category index
        category_index['categories'].append({
            'name': category,
            'count': len(category_data),
            'csv_path': os.path.join('categorized', category, 'channels.csv'),
            'html_path': os.path.join('categorized', category, 'channels.html')
        })
    
    # Write category index as JSON
    index_path = os.path.join(merged_folder, 'category_index.json')
    with open(index_path, 'w', encoding='utf-8') as f:
        json.dump(category_index, f, indent=2)
    
    # Create main HTML index
    create_main_html_index(merged_folder, category_index)
    
    printC(f"Categorized data written to {categorized_folder}", Fore.GREEN)

def create_html_file(data, file_path, category):
    """
    Create an HTML file with clickable links for the channels
    
    Args:
        data: DataFrame with channel data
        file_path: Path to write the HTML file
        category: Category name for the title
    """
    html_content = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Telegram Channels - {category.capitalize()}</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }}
        h1 {{
            color: #0088cc;
            border-bottom: 2px solid #0088cc;
            padding-bottom: 10px;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
        }}
        th, td {{
            padding: 12px 15px;
            border-bottom: 1px solid #ddd;
            text-align: left;
        }}
        th {{
            background-color: #0088cc;
            color: white;
        }}
        tr:hover {{
            background-color: #f5f5f5;
        }}
        a {{
            color: #0088cc;
            text-decoration: none;
        }}
        a:hover {{
            text-decoration: underline;
        }}
        .back-link {{
            margin-bottom: 20px;
            display: inline-block;
        }}
    </style>
</head>
<body>
    <a href="../index.html" class="back-link">← Back to Categories</a>
    <h1>Telegram Channels - {category.capitalize()}</h1>
    <p>Total channels in this category: {len(data)}</p>
    <table>
        <thead>
            <tr>
                <th>Channel Name</th>
                <th>Username</th>
                <th>Link</th>
            </tr>
        </thead>
        <tbody>
"""

    for _, row in data.iterrows():
        channel_name = row['Channel Name'] if pd.notna(row['Channel Name']) else 'Unknown'
        username = row['Channel Username'] if pd.notna(row['Channel Username']) else ''
        link = row['Link'] if pd.notna(row['Link']) else ''
        
        if link:
            html_content += f"""
            <tr>
                <td>{channel_name}</td>
                <td>{username}</td>
                <td><a href="{link}" target="_blank">Open Channel</a></td>
            </tr>"""
        else:
            html_content += f"""
            <tr>
                <td>{channel_name}</td>
                <td>{username}</td>
                <td>No link available</td>
            </tr>"""

    html_content += """
        </tbody>
    </table>
</body>
</html>
"""
    
    with open(file_path, 'w', encoding='utf-8') as f:
        f.write(html_content)

def create_main_html_index(merged_folder, category_index):
    """
    Create a main HTML index file that lists all categories
    
    Args:
        merged_folder: Path to the merged folder
        category_index: Dict with category information
    """
    # Sort categories by count
    sorted_categories = sorted(category_index['categories'], key=lambda x: x['count'], reverse=True)
    
    html_content = """<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Telegram Channels - Categories</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }
        h1 {
            color: #0088cc;
            border-bottom: 2px solid #0088cc;
            padding-bottom: 10px;
        }
        .category-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(250px, 1fr));
            gap: 20px;
            margin-top: 20px;
        }
        .category-card {
            border: 1px solid #ddd;
            border-radius: 8px;
            padding: 15px;
            transition: transform 0.3s ease;
        }
        .category-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 10px 20px rgba(0,0,0,0.1);
        }
        h2 {
            color: #0088cc;
            margin-top: 0;
        }
        .count {
            font-weight: bold;
            color: #666;
        }
        a {
            color: #0088cc;
            text-decoration: none;
        }
        a:hover {
            text-decoration: underline;
        }
    </style>
</head>
<body>
    <h1>Telegram Channels - Categories</h1>
    <div class="category-grid">
"""

    for category in sorted_categories:
        html_content += f"""
        <div class="category-card">
            <h2>{category['name'].capitalize()}</h2>
            <p class="count">{category['count']} channels</p>
            <p><a href="{category['html_path']}">View Channels</a></p>
        </div>"""

    html_content += """
    </div>
</body>
</html>
"""
    
    with open(os.path.join(merged_folder, 'index.html'), 'w', encoding='utf-8') as f:
        f.write(html_content)


if __name__ == '__main__':
    try:
        # Specify the folders and filename
        results_folder, merged_folder, merged_filename, main_directory_csv = 'results', 'merged', 'merged_channels.csv', 'channels.csv'
        merge_csv_files(results_folder, merged_folder, merged_filename, main_directory_csv)  # Call the function
    except Exception as e:
        printC(f"Error in merge_csv_files: {e}", Fore.RED)
        import traceback
        traceback.print_exc()
