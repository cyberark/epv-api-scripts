#########################################################################
#                                                                    	#
#                                                                    	#
#   Set-DomainUser			    				#
#                                                                    	#
#   Script to help with creation of connection components        	#
#            		     						#
#                                                                    	#
#                                          		         	#
#########################################################################

  .EXAMPLE 
  PS C:\> .\Add-PSMApplication.ps1 -Application (applications to install)

The script is provided in a zip file containing:
 - Readme.txt file.
 - Add-PSMApplication.ps1 - script to run
================================================

Mandatory parameters (Add-PSMApplication will prompt for this if not provided on the command line):
	Application - a comma-separated list of applications to install and/or configure

Other parameters vary based on the applications to install. For full details, see https://cyberark.my.site.com/s/article/How-to-use-Add-PSMApps