"""Azure Functions (Python v2 model) binding for the runner handlers.

Packaged at the zip root next to ``ingest_handler.py`` and
``detect_handler.py``. Service Bus triggers use an identity-based connection
(``ServiceBusConnection__fullyQualifiedNamespace``), so no connection string
is stored in app settings.
"""

from __future__ import annotations

import json
import logging

import azure.functions as func
import detect_handler
import ingest_handler

app = func.FunctionApp()


@app.service_bus_queue_trigger(
    arg_name="msg",
    queue_name="%INGEST_QUEUE_NAME%",
    connection="ServiceBusConnection",
)
def ingest(msg: func.ServiceBusMessage) -> None:
    result = ingest_handler.handle_ingest_messages([msg.get_body().decode("utf-8")])
    logging.info("runner-ingest %s", json.dumps(result, sort_keys=True))


@app.service_bus_queue_trigger(
    arg_name="msg",
    queue_name="%DETECT_QUEUE_NAME%",
    connection="ServiceBusConnection",
)
def detect(msg: func.ServiceBusMessage) -> None:
    result = detect_handler.handle_detect_messages([msg.get_body().decode("utf-8")])
    logging.info("runner-detect %s", json.dumps(result, sort_keys=True))
