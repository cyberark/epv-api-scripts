# Contributing to EPV API Scripts
👍🎉 First off, thanks for taking the time to contribute! 🎉👍

The following is a set of guidelines for contributing to EPV API Scripts on GitHub. These are mostly guidelines, not rules. Use your best judgment, and feel free to propose changes to this document in a pull request.

This repository is meant to hold sample scripts for using CyberArk REST API, you can find here different code examples for different use cases and would be great if you can contribute your own suggestions to new use cases.

For general contribution and community guidelines, please see the [community repo](https://github.com/cyberark/community).

## Table of Contents

- [Development](#development)
- [Testing](#testing)
- [Releases](#releases)
- [Contributing](#contributing)
	- [General Workflow](#general-workflow)
	- [Reporting Bugs](#reporting-bugs)

## Development

You can choose whatever coding language you like, we are using mostly PowerShell
Please create a new folder for your code and include a short README file that explains the use case and how to use the script. Feel free to use and copy the structure from other folders.

## Testing

You will be responsible testing your own code, please make sure to upload code that is tested and note in a README the minimum version required

## Contributing 
### General Workflow

1. [Fork the project](https://help.github.com/en/github/getting-started-with-github/fork-a-repo)
2. [Clone your fork](https://help.github.com/en/github/creating-cloning-and-archiving-repositories/cloning-a-repository)
3. Make local changes to your fork by editing or creating new files
3. [Commit your changes](https://help.github.com/en/github/managing-files-in-a-repository/adding-a-file-to-a-repository-using-the-command-line)
4. [Push your local changes to the remote server](https://help.github.com/en/github/using-git/pushing-commits-to-a-remote-repository)
5. [Create new Pull Request](https://help.github.com/en/github/collaborating-with-issues-and-pull-requests/creating-a-pull-request-from-a-fork)

From here your pull request will be reviewed and once you've responded to all feedback it will be merged into the project. 

Congratulations, you're a contributor! 🎉🎉🎉

### Reporting Bugs
This section guides you through submitting a bug report or an issue with one of the script published in this repository. Following these guidelines helps maintainers and the community understand your report, reproduce the behavior, and find related reports.

When you are creating a bug report, please include as many details as possible and make sure you run the script with Debug and Verbose logging (In all PowerShell scripts just add '-Debug -Verbose' at the end of the script command).

**Note**: If you find a Closed issue that seems like it is the same thing that you're experiencing, open a new issue and include a link to the original issue in the body of your new one.

**Before Submitting A Bug Report**
Run the script with Verbose logging.
Perform a cursory search to see if the problem has already been reported. If it has and the issue is still open, add a comment to the existing issue instead of opening a new one.
