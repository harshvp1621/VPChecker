# Installing Python Virtual Environment

We provide a dump of our virtual environment to ensure identical development
setups. You can use either `conda` or `python venv` to create and import our
environment. We recommend conda, and the steps to install and import our
environment are as follows:

1. Install Anaconda for Linux:
   https://www.anaconda.com/docs/getting-started/anaconda/install#linux-installer

2. Import the virtual environment:
   `conda env create -f environment.yml`
   The file `environment.yml` contains a dump of our virtual environment.

3. Activate the virtual environment:
   `conda activate supply_chain_py311`

4. Install ipykernel for the virtual environment and configure it to use
   `supply_chain_py311`
   `$ python3 -m pip install ipykernel'
   `$ python3 -m ipykernel install --user --name=supply_chain_py311`

5. If there are any issues with setting up Anaconda, you can also setup a
   regular Python 3.11 virtual environment and install all dependencies in
   requirements.txt 
