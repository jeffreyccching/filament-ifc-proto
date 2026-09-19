/// Each file in `compile_fail/` is one way to leak a secret or cause a side
/// effect from inside `pc_block!` / `#[side_effect_free_attr]`; each must be
/// rejected at compile time with the error recorded next to it.
#[test]
fn pc_block_rejects_leaks() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/compile_fail/*.rs");
}
