"""Five-line SDK example: protect a customer message, call your AI, restore the reply, log it.

    python -m pip install -e .            # once, from the project folder
    python examples/sdk_quickstart.py

The AI call below is a stand-in that just repeats placeholders back, so this runs offline.
Replace `my_ai` with your own model call.
"""
from ai_compliance import Guard, check, find_person


def my_ai(text: str) -> str:
    """Stand-in for a real model: replies using whatever placeholders it was given."""
    return f"Thanks. I have noted the details you sent: {text}"


guard = Guard(source="sdk-quickstart")

for message in ["Hi, I'm Aoife Brennan, PPS 1234567T. Please email my statement to aoife.b@gmail.com",
                "My online banking password is Dublin2024! and it doesn't work"]:
    safe = guard.protect(message)                    # 1. mask before the AI sees it
    reply = "" if safe.blocked else my_ai(safe.text)  # 2. your own model call
    answer = guard.restore(reply)                    # 3. real values back for the customer
    flags = guard.log(message, answer)               # 4. flags go to the compliance dashboard

    print("Customer typed:   ", message)
    print("AI model received:", "(nothing, blocked)" if safe.blocked else safe.text)
    print("Customer sees:    ", answer)
    print("Flags:            ", [f"{f['priority']}: {f['concern']}" for f in flags])
    print()

print("Quick check, nothing stored:", [f["concern"] for f in check("Card 4539 1488 0343 6467")])
print("Person finder:", find_person("aoife.b@gmail.com")["events"], "stored events mention aoife.b@gmail.com")
