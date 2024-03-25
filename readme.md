# NeatLabs Sensitive Data Detection Scanner

The NeatLabs Sensitive Data Detection Scanner is a powerful and user-friendly tool designed to help organizations and individuals identify and locate sensitive data within their files and directories. It provides a comprehensive solution for scanning various file formats, including text files (.txt), Word documents (.docx), and Excel spreadsheets (.xlsx), and detecting sensitive information based on customizable patterns.

## Why Use NeatLabs Sensitive Data Detection Scanner?

In today's digital landscape, protecting sensitive data is of utmost importance. Organizations handle a vast amount of sensitive information, such as personal identifiable information (PII), financial data, and confidential business records. Inadvertent exposure or mishandling of such data can lead to severe consequences, including data breaches, legal liabilities, and reputational damage.

The NeatLabs Sensitive Data Detection Scanner empowers organizations to proactively identify and manage sensitive data across their file repositories. By automating the scanning process and providing flexible customization options, the scanner helps ensure that sensitive information is properly identified, classified, and protected.

## Key Features

- **Comprehensive Scanning**: The scanner recursively scans directories and subdirectories, examining files of supported formats (.txt, .docx, .xlsx) for sensitive data.
- **Customizable Patterns**: Define sensitive data patterns using regular expressions, allowing you to tailor the scanner to detect specific types of information relevant to your organization.
- **Intuitive User Interface**: The scanner provides a user-friendly graphical user interface (GUI) built with the ttkbootstrap library, offering a modern and intuitive user experience.
- **Selective Scanning**: Choose specific sensitive data patterns to scan for, enabling targeted scanning based on your organization's requirements.
- **File Copying**: Easily copy files containing sensitive data to a separate directory for further analysis or secure storage.
- **Detailed Reporting**: Generate comprehensive reports of the scan results, including file paths, sensitive data types, and matches, facilitating data governance and compliance efforts.
- **Efficient Results Management**: Clear scan results with a single click, allowing you to start fresh scans effortlessly.

## Getting Started

### Prerequisites

- Python 3.x installed on your system.
- Required dependencies: `ttkbootstrap`, `python-docx`, `openpyxl`.

### Installation

1. Clone the repository or download the source code files.
2. Open a terminal or command prompt and navigate to the project directory.
3. Install the required dependencies by running the following command:
   ```
   pip install ttkbootstrap python-docx openpyxl
   ```

### Usage

1. Launch the NeatLabs Sensitive Data Detection Scanner by running the following command:
   ```
   python sensitive_data_scanner.py
   ```
2. The scanner window will appear, presenting you with various options and settings.
3. Click the "Scan Files" button to select the directory you want to scan for sensitive data.
4. Customize the sensitive data patterns you want to scan for by checking or unchecking the corresponding checkboxes in the "Sensitive Data Patterns" section.
5. Initiate the scanning process by clicking the "Scan Files" button.
6. The scan results will be displayed in the "Scan Results" text area, showing the file path, sensitive data type, and matches for each file containing sensitive data.
7. To copy files containing sensitive data to a separate directory, select the desired files in the "Scan Results" text area and click the "Copy Selected Files" button. Choose the destination directory when prompted.
8. To generate a detailed report of the scan results, click the "Generate Report" button and specify the location where you want to save the report file.
9. If you want to clear the scan results and start a new scan, click the "Clear Results" button.

## Customization

The NeatLabs Sensitive Data Detection Scanner allows you to customize the sensitive data patterns it scans for. To modify or add new patterns, open the `sensitive_data_scanner.py` file in a text editor and locate the `data_patterns` dictionary. Each pattern is defined as a regular expression and associated with a description. Update the dictionary according to your specific requirements.

Example:
```python
data_patterns = {
    r'\b\d{3}-\d{2}-\d{4}\b': 'Social Security Number',
    r'\b(?:\d{4}[-\s]?){3}\d{4}\b': 'Credit Card Number',
    r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b': 'Email Address',
    # Add more patterns here
}
```

## Contributing

We welcome contributions to enhance the functionality and usability of the NeatLabs Sensitive Data Detection Scanner. If you have any ideas, bug reports, or feature requests, please open an issue on the GitHub repository. If you would like to contribute code improvements or new features, feel free to submit a pull request.

When contributing, please adhere to the following guidelines:
- Follow the coding style and conventions used in the existing codebase.
- Provide clear and concise descriptions of your changes or additions.
- Test your modifications thoroughly to ensure they do not introduce new bugs.
- Document any new features or changes in the README.md file.

## License

The NeatLabs Sensitive Data Detection Scanner is released under the [MIT License](LICENSE). You are free to use, modify, and distribute the code for both commercial and non-commercial purposes.

## Contact

If you have any questions, suggestions, or feedback regarding the NeatLabs Sensitive Data Detection Scanner, please feel free to reach out to us.

We appreciate your interest in the NeatLabs Sensitive Data Detection Scanner and look forward to hearing from you!

Happy scanning and stay vigilant in protecting sensitive data!