#!/usr/bin/env python3
import argparse

# ---------- Core functionality ----------

class Calculator:
    """Simple calculator class."""
    def add(self, x, y):
        return x + y

    def multiply(self, x, y):
        return x * y

def greet(name: str) -> str:
    return f"Hello, {name}!"

# ---------- CLI interface ----------

def main():
    parser = argparse.ArgumentParser(description="Single-file CLI example")

    # Positional arguments
    parser.add_argument("x", type=float, help="First number")
    parser.add_argument("y", type=float, help="Second number")

    # Optional argument with choices
    parser.add_argument(
        "-o", "--operation",
        choices=["add", "multiply"],
        default="add",
        help="Operation to perform (default: add)"
    )

    # Optional flag
    parser.add_argument(
        "--greet",
        type=str,
        help="Print a greeting to the provided name"
    )

    args = parser.parse_args()

    # Handle greeting if requested
    if args.greet:
        print(greet(args.greet))

    # Perform the calculation
    calc = Calculator()
    if args.operation == "add":
        result = calc.add(args.x, args.y)
    else:
        result = calc.multiply(args.x, args.y)

    print(f"Result: {result}")

# ---------- Entry point ----------

if __name__ == "__main__":
    main()

