
------------------------------ INSTALATION ---------------------------------

For running this program it is required a python instalation > 3.6

In order to run the program and to avoid any problems with the host python
evironment it is recommended to follow these steps:

1. Create a virtual enviroment on a desired path. Recommended dir name .venv

python -m venv /path/to/dir/dir_name

This will create a directory in the specified path with the virtual env

2. Activate the virtual enviroment:

POSIX

bash/zsh	-> source <venv>/bin/activate
fish		-> source <venv>/bin/activate.fish
csh/tcsh 	-> source <venv>/bin/activate.csh
PowerShell Core -> <venv>/bin/Activate.ps1

Windows

cmd.exe 	-> <venv_path>\Scripts\activate.bat
PowerShell 	-> <venv_path>\Scripts\Activate.ps1

3. Once the activation has been performed install all the requirements

pip install -r requirements.txt

4. If everything works well the envronment is ready to execute the tool


*NOTE*: In order to remove the virtual environment just type on the console
"deactive" and later on delete the directory specified in the first step


------------------------------ EXECUTION ---------------------------------

In order to use the tool server.py must be executed before the client.py.
To specify the message to send you must edit the line 260 of the client.py 
file.


*NOTE* : Both Blockcypher and Pastebin API services are limited so check
the capacity analysis on the report to know the maximun ammount of information
that can be sent.
