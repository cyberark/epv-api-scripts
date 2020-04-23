# PAS REST API Mock Server

Use a local mock API server to develop and debug a lot faster your CyberArk PAS REST API applications or scripts.
Using a mock server you will not endanger any production environment and can real fast responses.
Edit and contribute to this mock API JSON with additional information and rules.

![screenshot](https://github.com/cyberark/epv-api-scripts/blob/MockServer/Mock%20Server/images/mockoon_pas_restapi.png)

## Requirements

- [*Mockoon*](#download-mockoon)
- JSON file of a [*PAS environment*](PAS REST API.json)

## Download Mockoon

You can get Mockoon from the official [website](https://mockoon.com/#download). Mockoon is also available through Homebrew `brew cask install mockoon`, Snap store `snap install mockoon`, Chocolatey `choco install mockoon` or AUR `yay -S mockoon-bin` (or any other AUR helper).

## Importing the environment

After installing Mockoon, go to 'Import/export'->Mockoon's format->Import from a file (JSON)
> The PAS REST API environment shuold be added to your mockoon server
![screenshot](https://github.com/cyberark/epv-api-scripts/blob/MockServer/Mock%20Server/images/import_menu.pngng)
Start the local mock API server and use it to debug you CyberArk REST API development

## License

Mockoon is licensed as MIT
The JSON file provided here is given based on the same license as the epv-api-scripts license