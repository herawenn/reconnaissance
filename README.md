# Interrogate: A Comprehensive Reconnaissance Tool

Interrogate is a powerful and flexible reconnaissance tool designed to gather information about a target domain. It performs DNS lookups, active scanning, and more to provide a comprehensive overview of the target's infrastructure.

## Features

- DNS and IP Discovery: Resolve domain names to IP addresses and follow CNAME records.
- Active Scanning: Utilize tools like Nmap, Nikto, and SSLScan to gather detailed information about open ports and services.
- Exploit Database Search: Search for known exploits related to identified services.
- Configurable Scanning Profiles: Customize the depth and breadth of scans with different Nmap profiles.
- API Integration: Leverage various APIs for enriched data gathering (requires API keys).

## Installation

### Prerequisites

- Python 3.8 or higher
- pip (Python package installer)
- Nmap, Nikto, and SSLScan installed and available in your system's PATH

### Setup

1. Clone the repository to your local machine:

   ```bash
   git clone https://github.com/herawenn/interrogate.git
   ```

2. Navigate to the project directory:

   ```bash
   cd interrogate
   ```

3. Install the required Python packages:

   ```bash
   pip install -r requirements.txt
   ```

4. Create a `config.ini` file from the provided example and add your API keys:

   ```bash
   cp config.ini.example config.ini
   ```

   Edit `config.ini` and add your API keys for the services you plan to use.

## Usage

To run Interrogate, use the following command:

```bash
python main.py -d example.com [options]
```

### Options

- `-d, --domain`: The target domain to analyze (required).
- `-n, --name-server`: Specific DNS server for queries (e.g., 8.8.8.8).
- `-o, --output`: Directory to save results (default: `recon_results`).
- `--skip-nmap`: Skip Nmap and all related active scans.
- `--nmap-profile`: Nmap scan profile (choices: `light`, `default`, `full`, `custom`; default: `default`).
- `--nmap-args`: Custom Nmap arguments for the 'custom' profile.
- `--nikto`: Run Nikto scans on identified web services.
- `--sslscan`: Run SSLScan on identified SSL/TLS services.

### Example

```bash
python main.py -d example.com --nikto --sslscan
```

This command will perform a reconnaissance scan on `example.com`, including Nikto and SSLScan scans on identified services.

## Contributing

Contributions are welcome! Please fork the repository and submit a pull request with your changes. For major changes, please open an issue first to discuss what you would like to change.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

