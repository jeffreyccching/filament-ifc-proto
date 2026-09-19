# Calendar - Secure Mutual Availability Finder

This example demonstrates using the lattice-based type system and label-based security model from the `typing_rules` library to build a secure calendar system that finds mutual availability between two people.

## Overview

The calendar example shows how to:
- **Separate Sensitive Data**: Alice's and Bob's calendars are labeled with different security levels (A and B)
- **Type-Safe Access**: The type system ensures data can only be accessed at appropriate security levels
- **Compute Shared Results**: Use label joins to safely compute mutual availability at the AB level
- **Prevent Information Leaks**: The compiler enforces that Alice's data at level A cannot accidentally flow to level B

## Key Concepts

### Security Labels

- **Label A**: Alice's private data (her availability)
- **Label B**: Bob's private data (his availability)  
- **Label AB**: Represents the join of A and B (shared/high-security context)
- **Public**: Unrestricted data

### The Lattice

```
      AB (Top - Shared Secret)
     /  \
    A    B
     \  /
    Public (Bottom)
```

When you access both Alice's and Bob's calendars together, you're automatically in the AB context, which is the "least upper bound" (join) of their security levels.

## How It Works

1. **Create Calendars**: Each person gets a calendar labeled with their own security level
   ```rust
   let alice_cal: Calendar<A> = Calendar::new(alice_events);
   let bob_cal: Calendar<B> = Calendar::new(bob_events);
   ```

2. **Access Shared Data**: When computing mutual availability, both calendars are accessed at level AB
   ```rust
   find_mutual_availability(&alice_cal.events.value, &bob_cal.events.value)
   ```

3. **Type Safety**: The compiler ensures:
   - You cannot store Alice's calendar in a Bob-labeled variable
   - You cannot accidentally leak A-labeled data to a Public context
   - Information flows only according to the security lattice

## Running

```bash
cargo run -p calendar
```

## Example Output

```
╔═══════════════════════════════════════════════════════╗
║        Calendar - Secure Mutual Availability         ║
║         Using Label-Based Type System                ║
╚═══════════════════════════════════════════════════════╝

Alice and Bob have 3 mutual available days
```

## Security Properties

✓ **No Implicit Information Leaks**: Data labeled A cannot reach context B  
✓ **Explicit Joins**: Only operations that explicitly join levels can access mixed data  
✓ **Compile-Time Enforcement**: All security violations caught at compile time  
✓ **Type-Driven Design**: Security is part of the type, not runtime checks  

## Implementation Details

- `Labeled<T, L>`: Wraps data `T` with security label `L`
- `Calendar<L>`: A calendar whose event map is labeled with level `L`
- `HashMap<String, Availability>`: Maps day names to availability status
- The join operation (AB) allows safe access to both calendars simultaneously

