# PowerShell Scripts Repository

## Description
This repository contains a collection of PowerShell scripts for various automation tasks, system administration, and troubleshooting.

## Features
- Useful PowerShell scripts for different scenarios
- Well-documented and easy-to-use scripts
- Regularly updated with new scripts and improvements

## Installation
1. Clone the repository:
   ```sh
   git clone https://github.com/your-username/PowerShell-Scripts.git
   ```
2. Navigate to the directory:
   ```sh
   cd PowerShell-Scripts
   ```
3. If required, unblock scripts:
   ```powershell
   Get-ChildItem -Path .\ -Recurse | Unblock-File
   ```

## Usage
Run a script with:
```powershell
.\script-name.ps1
```
Or, if execution policy restrictions apply:
```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\script-name.ps1
```

## Contributing
Contributions are welcome! Follow these steps:
1. Fork the repository.
2. Create a new branch (`git checkout -b feature-name`).
3. Commit your changes (`git commit -m "Added new PowerShell script"`).
4. Push to the branch (`git push origin feature-name`).
5. Open a Pull Request.

## License
This project is licensed under the [MIT License](LICENSE).
