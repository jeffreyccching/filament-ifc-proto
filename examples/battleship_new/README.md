# Battleship — Filament port of Cocoon's case study

A two-player Battleship game where each player's ship positions are secret from the
opponent. This is Filament's port of the same case study Cocoon uses
(`ifc_examples/battleship` in the Cocoon repository), kept deliberately close to it so the
two can be compared.

## The policy

Each player's `ship_positions` is labeled with that player's level (`A` for one, `B` for the
other) and must stay hidden from the opponent. The only thing that may be revealed is whether
a given guess hit — which is the game.

```rust
struct Player<L: Label> {
    ship_positions: Labeled<Grid<bool>, L>,   // secret
    guesses: Grid<CellStatus>,                // public: announced to the opponent
}
```

The grid is 10×10 and the five ships (carrier 5, battleship 4, cruiser 3, submarine 3,
destroyer 2) occupy 17 cells in total, which is what `did_win` counts.

## What this example does and does not use

| Construct | Count | Why |
|---|---|---|
| `Labeled<T, L>` | on `ship_positions` | the secret |
| `declassify` | 2 | one per game loop, revealing hit/miss — intentional, and the point of the game |
| `pc_block!` | 0 | no branch or loop condition depends on a labeled value |
| `#[side_effect_free_attr]` | 0 | no code runs inside a `pc_block!` |
| `unchecked_operation` | 0 | nothing needs to bypass a check |

The two `declassify` calls are the entire trusted surface. See `examples/calendar` for the
example that does exercise `pc_block!`.

## Why no block is needed during ship placement

Ship placement runs on an **unlabeled** grid and is wrapped once at the end:

```rust
let mut raw_positions: Grid<bool> = [[false; GRID_SIZE]; GRID_SIZE];
for ship in &ships {
    let placement = random_placement(&raw_positions, ship);
    place_ship(&mut raw_positions, &placement);
}
Player { ship_positions: Labeled::<Grid<bool>, L>::new(raw_positions), .. }
```

Nothing labeled flows *into* this. `Player::new` takes no arguments, and its only inputs are a
constant array of ship sizes and `util::random`, which is raw `usize` in and out. The grid
becomes secret by declaration, not by derivation, so there is no flow for the system to check
until `Labeled::new` stamps the policy on.

Cocoon reaches the same place differently: `wrap_secret` is only callable inside a
`secret_block!`, so the whole placement loop must sit in one, every helper must carry
`#[side_effect_free_attr]`, and its `place_ship` needs `unchecked_operation` for the grid write
(Cocoon Figure 6a). The helper signatures here match Cocoon's — all take raw `&Grid<bool>` —
because inside a secret block Cocoon's grid is raw too.

This is contingent on placement being secret-independent, which holds here. If placement
consumed a secret (a labeled seed, say), the rejection-sampling loop in `random_placement`
would branch on a labeled value and would need a `pc_block!` — and `util::random` mutates RNG
state, so it would then need an escape hatch, exactly as in Cocoon.

## Structure

```
battleship_new/
├── Cargo.toml
├── README.md
└── src/
    ├── main.rs   # game logic, placement, the two game loops
    └── util.rs   # util::random
```

The two players run as threads in a single process, communicating over `session_types`
channels, with the protocol encoded in the `PlayerA` / `PlayerB` session types.

## Building and running

```bash
cargo build -p battleship_new
cargo run   -p battleship_new
```

Both players read guesses from stdin in the format `<row letter> <column>`, e.g. `a 1`
(rows `a`–`j`, columns 1–10). Play continues until one side has 17 hits.

## Tests

```bash
cargo test -p battleship_new
```

`ships_do_not_overlap` builds 200 players and asserts each grid has exactly 17 occupied cells.
This is a regression guard: `legal_placement` previously ignored its `grid` argument, so ships
could overlap and a game could be unwinnable.
