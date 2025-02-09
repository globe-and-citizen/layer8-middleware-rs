# Design Document

- [x] We need to create a special file say: `~/.l8proxy/proc.json` if not exists. This needs to be platform agnostic.
    The file will be expected to have the following format:

    ```json
    {
        "version": "0.1.0",
        "proxies": [
            {
                "port": 80,
                "service_port": 8090,
            }
        ],
    }
    ```

- [ ] To start the server, run the command below:

    ```bash
    l8proxy start --port 80 --service-port 8090 -d
    ```

    This will start the server on port 80 and forward processed requests to the service_port (in the above example, 8090) . The `-d` flag is to daemonize the process. The process' port will be written to the `~/.l8proxy/proc.json` file.
    Using this information the process can be stopped when daemonized.
    A proxy started on port 80 is expected to receive HTTP traffic.
    A proxy started on port 443 is expected to receive HTTPs traffic.

- [ ] To stop the server, run the command below:

    ```bash
    l8proxy stop --port 80
    ```

    > If `$ l8proxy stop` is called without the `--port` flag, it will stop all the l8proxy servers running if not specified
