use arinsal_bifs::{Ctx, DeferredTrap, ProcessHeapHandle, UnicodeStep, lookup, unicode_resume};
use arinsal_difftest::{CallResult, RefErl};
use arinsal_etf::OwnedTerm as O;
use arinsal_term::{ProcessHeap, from_owned, to_owned};
use similar_asserts::assert_eq;

#[test]
fn utf8_size_and_fill_match_otp_with_and_without_traps() {
    let reference = RefErl::shared().expect("OTP 29 reference");
    let cases = [
        "[]",
        "[65,233,8364,128512,90]",
        "[lists:duplicate(64,65)]",
        "[lists:duplicate(65,65)]",
        "[lists:duplicate(1000,65), [233,8364,128512], <<\"tail\">>]",
        "[lists:duplicate(1000,233), <<226>>, [[], <<130>>, <<172>>], 90]",
        "[lists:duplicate(1000,65), <<226,130>>, [[], 90]]",
        "[lists:duplicate(1000,65), <<226,130>>, <<255,90>>]",
        "[lists:duplicate(1000,65), <<255,90>>]",
        "[lists:duplicate(1000,65), <<240,144,128>>]",
        "[lists:duplicate(1000,65), 16#D800, 90]",
        "[lists:duplicate(1000,65), 1 bsl 100, invalid]",
        "[lists:duplicate(1000,65) | <<233,90>>]",
        "[lists:duplicate(1000,65), <<(binary:copy(<<226,130,172>>,1000))/binary>>]",
    ];
    for expression in cases {
        let input = reference.eval(expression).expect("input");
        for encoding in ["utf8", "latin1"] {
            let args = [input.clone(), O::atom(encoding)];
            let expected = reference.call("unicode", "characters_to_binary", &args);
            for budget in [1, 5, 50, 4000, usize::MAX] {
                let mut heap = ProcessHeap::with_words(1024);
                let mut allocator = ProcessHeapHandle(&mut heap);
                let input = from_owned(&input, &mut allocator).unwrap();
                let encoding = from_owned(&O::atom(encoding), &mut allocator).unwrap();
                let mut state = arinsal_bifs::BifState::default();
                let mut ctx = Ctx::new(&mut allocator, &mut state);
                ctx.set_reduction_budget(budget);
                let value = lookup("unicode", "characters_to_binary", 2).unwrap()(
                    &mut ctx,
                    &[input, encoding],
                )
                .unwrap();
                let mut step = match ctx.take_deferred().map(|trap| *trap) {
                    Some(DeferredTrap::Unicode(cont)) => UnicodeStep::More(cont),
                    None => UnicodeStep::Done(value),
                    _ => panic!("unexpected continuation"),
                };
                let mut slices = 0;
                let actual = loop {
                    match step {
                        UnicodeStep::Done(value) => break to_owned(value).unwrap(),
                        UnicodeStep::More(cont) => {
                            slices += 1;
                            assert!(slices < 10000, "conversion makes progress");
                            ctx.set_reduction_budget(budget);
                            step = unicode_resume(&mut ctx, &cont);
                        }
                    }
                };
                assert_eq!(
                    CallResult::Ok(actual),
                    expected,
                    "{expression}, budget={budget}"
                );
            }
        }
    }
}
