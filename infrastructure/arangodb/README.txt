# Installing ArangoDB

1. Run the `install_arango.sh` script to install the ArangoDB Community
   Edition:  
   `$ ./install_arango.sh`

2. The script requires root privileges to run `apt update` and perform the
   installation.

3. The first-time installation of ArangoDB is interactive—it prompts you to set
   a password for the `root` ArangoDB user.

4. Set an appropriate password and make note of it; you will need it whenever
   you connect to the database in subsequent stages.

5. After installation, the `arangodb` service runs as a daemon and starts
   listening on port 8529. The web interface is accessible at
   `http://localhost:8529`, where you can log in with the `root` username and the
   password you set earlier.

---

# Restoring VPChecker’s Knowledge Graph (Importing the database from dump
  files)

1. ArangoDB is a graph database. We extracted call graphs of over 24,000
   binaries and, using a set of scripts, aggregated all call graphs into a unified
   database.

2. We provide the scripts for call-graph creation and database creation
   separately; however, in this step you can simply restore the database we used
   to produce the results in our paper.

3. Run the `import_dump.sh` script to restore the dump files in `../../../artifact/db_dump`.  
   Ensure that ArangoDB is up and running on port 8529. You can verify this by
   logging in as `root` at `http://localhost:8529`.  
   `$ ./import_dump.sh`
   
   3.1 We have hardcoded the credentials `root:root` in the import_dump.sh
       script. Please update the password with whetever value you set during
       installation.

   3.2 Note that the import might take a while depending on the available
       resources. The script uses `nproc` to determine the number of threads used for
       the restore. On a 14-core Intel Ultra 7 165U machine, the import took around 32
       minutes. A total of 35.7 GB of data will be extracted. The import will end with
       a log message similar to:

   `2025-09-09T23:06:25.706750Z [1483216-1] INFO [a66e1] {restore} Processed 26
    collection(s) from 1 database(s) in 1876.92 s total time. Read 35.7 GB from
    datafiles (after decompression), sent 4276 data batch(es) of 35.7 GB total
    size.`

4. The import restores the `sysfilter` database with the graphs `call_graph` and `ldd_graph`.

5. After the restore completes, open the ArangoDB UI and verify that the
   following graphs were loaded by clicking the **Graphs** button on the left
   pane:  
   5.1 `call_graph`: The function-level call graph of all ELF64 binaries in our dataset.  
   5.2 `ldd_graph`: The ELF-level dependency graph of all ELF64 binaries in our dataset.

All evaluations were performed by running various queries on the database
installed and set up above.
