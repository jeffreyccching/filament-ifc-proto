# Battleship New - Security-Typed Rust Implementation

## Overview

This project is a new implementation of the classic Battleship game using Rust with **security typing** and **information flow control (IFC)** features from the `typing_rules` and `macros` libraries.

It follows the same game logic as the original `battleship` example but with syntax and patterns strictly adhering to:
- **Macro library** (`macros::pc_block`) for program counter tracking and implicit flow analysis
- **Typing rules library** (`typing_rules::*`) for information flow control with security lattices

## Key Features

### 1. **Security-Typed Data**
- Uses `Labeled<T, L>` wrapper to attach security labels to data
- Supports multiple security levels: `Public`, `A`, `B`, and `AB` (join of A and B)
- Enforces explicit flow control via `FlowsTo` trait
- Enforces implicit flow control via PC (program counter) tracking

### 2. **Game Logic**
- Two players (Alice and Bob) play battleship on 5x5 grids
- Each player has secret ships placed on their board
- Players exchange guesses via message channels
- Game validates hits/misses with information flow control

### 3. **Program Counter Blocks**
- Uses `pc_block!` macro to track implicit information flows
- Prevents data leakage through control flow (if/else conditions)
- Enforces that secret conditions don't affect public writes

## Project Structure

```
battleship_new/
├── Cargo.toml          # Project manifest
└── src/
    └── main.rs        # Main game implementation
```

## Building and Running

### Build the project:
```bash
cd /winhomes/jcc150/real_static_rust
cargo build -p battleship_new
```

### Run the game:
```bash
cargo run -p battleship_new
```

## Game Flow

1. Alice and Bob each initialize a player with secret ship placements
2. Alice starts by guessing coordinates (0,0), then (1,1), then (2,2)
3. Bob responds with hits/misses, then makes his own guesses
4. Game runs for 3 rounds
5. All secret data is properly labeled and flow-controlled

## Type Safety

The implementation demonstrates:
- **Generic label parameters** `<L: Label>` for secure data containers
- **PcContext** for tracking program counter security level
- **Implicit flow tracking** through `pc_block!` macro
- **Declassification** where secrets are safely downgraded to public information before transmission

## Differences from Original Battleship

Both implementations share identical game logic, but `battleship_new`:
- Relies more heavily on the `pc_block!` macro for control flow security
- Uses simplified trait bounds that leverage `Public: FlowsTo<L>` constraint
- Demonstrates how information flow control integrates with game state mutations
