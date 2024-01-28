# PAS REST API Mock Server
## Main Capabilities
Use a local mock API server to develop and debug a lot faster your CyberArk PAS REST API applications or scripts.
Using a mock server enables you no to endanger any production environment and to benefit faster responses.
Edit and contribute to this mock API JSON with the additional information and rules.

![screenshot](https://github.com/cyberark/epv-api-scripts/blob/master/Mock%20Server/images/mockoon_pas_restapi.png)

## Requirements

- [*Mockoon*](#download-mockoon)
- .json file of a [*PAS environment*](PAS REST API.json)

## Download Mockoon

You can get Mockoon from the official [website](https://mockoon.com/#download). Mockoon is also available through:
- Homebrew `brew cask install mockoon`,
- Snap store `snap install mockoon`, 
- Chocolatey `choco install mockoon`
- AUR `yay -S mockoon-bin` (or any other AUR helper).


## Importing the environment

After installing Mockoon, go to 'Import/export'->Mockoon's format->Import from a file (JSON).
> The PAS REST API environment should be added to your mockoon server
![screenshot](https://github.com/cyberark/epv-api-scripts/blob/master/Mock%20Server/images/import_menu.png)

Start the local mock API server and use it to debug you CyberArk REST API development.

## Mock PVWA Server version
- PVWA version 11.1
- All API will work with versions higher than 11.1, some might have more properties.

## Licence

- Mockoon is licensed as MIT.
- The .json file provided here is given based on the same licence as the epv-api-scripts licence.
