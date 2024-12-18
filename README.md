# FalconHunter

FalconHunter is an active reconnaissance and vulnerability scanner framework designed to assist security professionals in identifying and assessing potential security risks.

## Features

- **Active Reconnaissance**: Gather information about target systems.
- **Vulnerability Scanning**: Detect common vulnerabilities.
- **Modular Design**: Easy to use

## Installation

Clone the repository and install dependencies:

```bash
git clone https://github.com/OctaYus/FalconHunter.git
cd FalconHunter
pip install -r requirements.txt
bash instsll.sh
```

## Usage

- Run the main script for list of domains with desired options:

```bash
python3 main.py -d/--domains, -templates/--nuclei-templates, -sstimap/--sstimap-path, -o/--output
```
- For help: 
```bash
python3 main.py -h 
```


## Contributing

Feel free to submit issues or pull requests.

## License

This project is licensed under the MIT License.

For more details, visit the [GitHub repository](https://github.com/OctaYus/FalconHunter).
