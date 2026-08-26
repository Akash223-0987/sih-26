"""
PyTrace Example FastAPI Application.

Demonstrates:
1. One-line automatic HTTP instrumentation: PyTrace(app)
2. Context-aware structured business logging: logger.info(...), logger.error(...)
3. Dynamic request attribute enrichment: update_request_attribute(...)
4. Error and exception tracing.

Run with:
    python examples/fastapi_demo.py
or:
    uvicorn examples.fastapi_demo:app --reload --port 8000
"""

import uvicorn
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from pytrace import PyTrace, logger, update_request_attribute

app = FastAPI(
    title="E-Commerce API with PyTrace Telemetry",
    description="Enterprise service demonstration instrumented with PyTrace",
    version="1.0.0",
)

# Initialize PyTrace automatic instrumentation
# Automatically captures HTTP requests, latencies, status codes, and trace context.
# Structured events are written to logs/application.log and stdout.
PyTrace(
    app,
    service_name="ecommerce-service",
    environment="development",
)


class OrderRequest(BaseModel):
    customer_id: str
    items: list[str]
    total_amount: float


@app.get("/")
def root():
    """Health check endpoint."""
    return {"status": "ok", "service": "ecommerce-service", "telemetry": "pytrace"}


@app.get("/api/users/{user_id}")
def get_user(user_id: int):
    """Retrieve user details and log business event."""
    update_request_attribute("user_tier", "gold")

    logger.info(
        "User profile retrieved",
        user_id=user_id,
        region="ap-south-1",
        cache_hit=True,
    )

    return {
        "user_id": user_id,
        "name": "Aryan",
        "role": "Engineer",
        "tier": "gold",
    }


@app.post("/api/orders")
def create_order(order: OrderRequest):
    """Simulate order placement with structured telemetry."""
    order_id = f"ORD-{user_id_hash(order.customer_id)}"

    update_request_attribute("order_id", order_id)
    update_request_attribute("customer_id", order.customer_id)

    logger.info(
        "Payment verified and inventory reserved",
        order_id=order_id,
        amount=order.total_amount,
        items_count=len(order.items),
        gateway="stripe",
    )

    return {
        "order_id": order_id,
        "status": "confirmed",
        "total_amount": order.total_amount,
    }


@app.get("/api/simulate-error")
def simulate_error():
    """Endpoint that raises an uncaught exception to demonstrate stacktrace capture."""
    logger.warn("Simulating database failure for forensic testing")
    raise ConnectionRefusedError("Could not connect to primary PostgreSQL replica at 10.0.1.5:5432")


@app.get("/api/status/{code}")
def status_endpoint(code: int):
    """Simulate custom HTTP status codes."""
    if code >= 400:
        raise HTTPException(status_code=code, detail=f"Custom error response {code}")
    return {"status_code": code, "message": "Success"}


def user_id_hash(customer_id: str) -> int:
    return abs(hash(customer_id)) % 100000


if __name__ == "__main__":
    print("\nStarting PyTrace Demo FastAPI Server on http://127.0.0.1:8000 ...")
    print("Logs will be streamed to console and appended to logs/application.log\n")
    uvicorn.run(app, host="127.0.0.1", port=8000)
