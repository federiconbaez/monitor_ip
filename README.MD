# IP Threat Checker - Advanced and Scalable Python Implementation

![Python](https://img.shields.io/badge/Python-3.9%2B-blue.svg) ![License](https://img.shields.io/badge/License-MIT-green.svg) ![Version](https://img.shields.io/badge/Version-1.0.0-orange.svg)

IP Threat Checker is a Python-based solution designed to verify if an IP address is blacklisted or associated with malicious activities. The project supports multiple sources of threat detection, including external APIs and local threat databases, offering flexibility, scalability, and performance.

---

## 🚀 Features

- **API Integration**: Seamless integration with external services such as AbuseIPDB and IPinfo.
- **Local Threat Database**: Offline checking using public blacklists like Spamhaus.
- **Caching**: Built-in caching with `@lru_cache` for performance optimization.
- **Error Handling**: Robust exception management for API failures or network issues.
- **Extendable**: Easy to add new threat sources with minimal changes.
- **Efficient**: Implements modern Python practices and optimization techniques.

---

## 📋 Table of Contents

- [Installation](#installation)
- [Usage](#usage)
- [Configuration](#configuration)
- [API Sources Supported](#api-sources-supported)
- [Local Threat List](#local-threat-list)
- [Contributing](#contributing)
- [License](#license)

---

## 🔧 Installation

### Prerequisites

- Python 3.9 or higher
- `pip` package manager

### Clone the Repository

```bash
git clone https://github.com/federiconbaez/monitor_ip.git
cd ip-threat-checker
