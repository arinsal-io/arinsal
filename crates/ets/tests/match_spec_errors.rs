//! Differential tests of the match-spec compiler's error reporting against OTP 29.1.1:
//! `erlang:match_spec_test/3` results, error lists included, for valid and invalid
//! specifications of both dialects.

use arinsal_difftest::{CallResult, RefErl};
use arinsal_etf::OwnedTerm;
use arinsal_ets::match_spec::{MatchDialect, match_spec_test};
use arinsal_term::{VecHeap, from_owned, to_owned};

const SPECS: &str = r#"
-module(ms_error_fixture).
-export([specs/0]).

specs() ->
  [
   %% valid
   [{{'$1','$2'},[{'>','$1',0}],['$_']}],
   [{{'$1','$2'},[],['$$']}],
   [{{'$1','$2'},[],[{{'$2','$1'}}]}],
   [{'_',[],[true]}],
   [{'$1',[],['$1']}],
   [{#{a=>'$1'},[],['$1']}],
   [{{'$1',{'$2'}},[{is_integer,'$1'},{'orelse',{'>','$1',3},{'<','$2',1}}],[{const,[1,2]}]}],
   [{{'$1','$2'},[],[#{a=>'$1', b=>[{const,x}]}]}],
   [{{'$1','$2'},[],[[ '$1' | '$2'] ]}],
   [{{'$1','$2'},[{'andalso','$1','$2'}],[{'and', true, '$1'}]}],
   [{{'$1','$2'},[],[{'or', false, '$1'}, {'andthen', true, '$2'}]}],
   [{{'$1','$2'},[],[{element,1,'$_'}]}],
   [{{'$100','$1'},[],['$100','$1']}],
   [{{'$100','$1000'},[{'>','$1000','$100'}],['$1000']}],
   [{{'$100','$1000'},[],['$1001']}],
   [{{'$100'},[{foo,'$1000'}],[{bar}]}],
   %% shape errors
   bad, [], [bad], [{a,b}], [{a,b,c,d}], [{{'$1'},[],[true]}|x], [{{'$1'},[],[true]}, bad],
   [{{'$1'},bad,[true]}], [{{'$1'},[true|x],[true]}], [{{'$1'},[],bad}], [{{'$1'},[],[true|x]}],
   [{{'$1'},[],[]}], [{{'$1'},[],[true]}, {{'$2'},[],[]}],
   %% unbound variables and bad functions
   [{{'$1'},[],['$2']}],
   [{{'$1'},[{'>','$1','$2'}],['$3']}],
   [{{'$1'},[],[{{'$7'}}]}], [{{'$1'},[],[[a,'$7']]}], [{{'$1'},[],[#{a=>'$7'}]}],
   [{{'$1'},[],[{foo,'$1'}]}], [{{'$1'},[],[{foo}]}], [{{'$1'},[],[{foo,1,2,3,4}]}],
   [{{'$1'},[{foo,'$1'}],[true]}, {{'$2'},[{bar,'$2'}],[true]}],
   [{{'$1'},[{'+','$1',1,2}],[true]}], [{{'$1'},[{'=='}],[true]}], [{{'$1'},[{is_atom}],[true]}],
   [{{'$1'},[{'Foo bar', 1}],[true]}], [{{'$1'},[{'$1', 1}],[true]}],
   [{{'$1'},[{foo,"abc",<<"x">>,#{a=>1},{1,2},[a|b],2.5}],[true]}],
   [{{'$1'},[],[{'$1'}]}], [{{'$1'},[],[{1}]}], [{{'$1'},[],[{}]}], [{{'$1'},[],[{"x"}]}],
   [{{'$1'},[],[{'and'}]}], [{{'$1'},[],[{'or'}]}], [{{'$1'},[],[{'andalso'}]}],
   [{{'$1'},[],[{'andthen'}]}], [{{'$1'},[],[{'orelse'}]}],
   [{{'$1'},[],[{const}]}], [{{'$1'},[],[{const,1,2}]}], [{{'$1'},[],[{self,1}]}],
   [{{'$1'},[],[{const,[1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33,34,35,36],x}]}],
   [{{'$1'},[],[{const,1234567890123456789012345678901234567890,1234567890123456789012345678901234567890}]}],
   [{{'$1'},[],[{const,'a long atom name with spaces and \\quotes\\ and more more more more more more more more',b}]}],
   [{{'$1'},[],[{const,1.5,-2.5e100}]}], [{{'$1'},[],[{const,<<1:3>>,<<>>,<<1,2,3>>,<<"a\"b">>}]}],
   [{{'$1'},[],[{const,"a\nb\"c",[1000,2],[a|b],'\n\'x','',#{a=>1,b=>[]}, 'Ünï', 'é'}]}],
   [{{'$1'},[],[{const,fun lists:map/2}]}],
   %% maps in heads
   [{#{'$1'=>a},[],[true]}], [{#{'_'=>a},[],[true]}], [{#{a=>'$1'},[],['$2',{foo,x},{bar}]}],
   [{#{a=>#{'$1'=>b}},[],[true]}],
   [{{#{'$1'=>b}},[],[true]}],
   %% '$_' and '$$' in heads and elsewhere
   [{'$_',[],[true]}], [{'$$',[],[true]}], [{{'$_'},[],[true]}], [{{'$$'},[],['$$']}],
   [{{'$1'},[{is_atom,'$_'}],['$_']}],
   %% several clauses, errors after the first failing clause are not reported
   [{{'$1'},[{foo}],[{foo},{bar,'$3'}]}, {{'$1'},[],[true]}],
   [{{'$1'},[],[true]}, {{'$5'},[],['$6']}, {{'$7'},[{foo}],['$8']}],
   [{{'$1'},[],[true]}, {{'$1'},[],[{self,1}]}, {{'$1'},[{bar}],[{bar}]}],
   %% special forms of the trace dialect used in the table dialect and the other way
   [{{'$1'},[],[{return_trace}]}], [{{'$1'},[{return_trace}],[true]}],
   [{{'$1'},[],[{exception_trace}]}], [{{'$1'},[],[{return_trace,1}]}],
   [{{'$1'},[],[{message,'$1'}]}], [{{'$1'},[{message,'$1'}],[true]}], [{{'$1'},[],[{message}]}],
   [{{'$1'},[],[{display,'$1'}]}], [{{'$1'},[{display,'$1'}],[true]}], [{{'$1'},[],[{display}]}],
   [{{'$1'},[],[{is_seq_trace}]}], [{{'$1'},[{is_seq_trace}],[true]}], [{{'$1'},[],[{is_seq_trace,1}]}],
   [{{'$1'},[],[{set_seq_token,label,1}]}], [{{'$1'},[],[{set_seq_token,label}]}],
   [{{'$1'},[{set_seq_token,label,1}],[true]}],
   [{{'$1'},[],[{get_seq_token}]}], [{{'$1'},[],[{get_seq_token,1}]}],
   [{{'$1'},[],[{process_dump}]}], [{{'$1'},[],[{process_dump,1}]}],
   [{{'$1'},[],[{enable_trace,send}]}], [{{'$1'},[],[{enable_trace,self(),send}]}],
   [{{'$1'},[],[{enable_trace}]}], [{{'$1'},[],[{disable_trace,send}]}],
   [{{'$1'},[],[{disable_trace,self,send}]}], [{{'$1'},[],[{disable_trace}]}],
   [{{'$1'},[],[{trace,[a],[b]}]}], [{{'$1'},[],[{trace,[a]}]}],
   [{{'$1'},[],[{trace,1,[a],[b]}]}],
   [{{'$1'},[],[{caller}]}], [{{'$1'},[],[{caller,1}]}], [{{'$1'},[],[{caller_line}]}],
   [{{'$1'},[],[{caller_line,1}]}],
   [{{'$1'},[],[{current_stacktrace}]}], [{{'$1'},[],[{current_stacktrace,3}]}],
   [{{'$1'},[],[{current_stacktrace,-1}]}], [{{'$1'},[],[{current_stacktrace,a}]}],
   [{{'$1'},[],[{current_stacktrace,1,2}]}],
   [{{'$1'},[],[{silent,true}]}], [{{'$1'},[],[{silent}]}],
   [{{'$1'},[],[{get_tcw}]}], [{{'$1'},[{get_tcw}],[true]}], [{{'$1'},[],[{set_tcw,1}]}],
   [{{'$1'},[{set_tcw,1}],[true]}], [{{'$1'},[],[{set_tcw}]}],
   %% trace heads
   [{['$1','$2'],[],['$1']}], [{['$1'|'_'],[],['$1']}], [{['$1'|'$2'],[],['$1']}],
   [{['$1','$2'|x],[],['$1']}], [{[],[],[true]}], [{'_',[],[true]}], [{'$1',[],['$1']}],
   [{{'$1'},[],[true]}], [{[a|b],[],[true]}], [{#{a=>1},[],[true]}], [{[a,b],[{foo}],[true]}],
   [{[a,b],[],[{message,'$1'}]}], [{[a,b],[],[{message,true}]}],
   [{[a,b],[],[]}], [{[a,b],[],bad}], [{[a,b],bad,[]}]
  ].
"#;

fn list_of(term: &OwnedTerm) -> Vec<OwnedTerm> {
    match term {
        OwnedTerm::List { elems, .. } => elems.clone(),
        OwnedTerm::Nil => Vec::new(),
        other => panic!("not a list: {other:?}"),
    }
}

/// Maps compare equal whatever order the two runtimes enumerate their atom keys in.
fn canon(term: &OwnedTerm) -> OwnedTerm {
    match term {
        OwnedTerm::Map(pairs) => {
            let mut pairs: Vec<_> = pairs.iter().map(|(k, v)| (canon(k), canon(v))).collect();
            pairs.sort_by_key(|pair| format!("{pair:?}"));
            OwnedTerm::Map(pairs)
        }
        OwnedTerm::Tuple(items) => OwnedTerm::Tuple(items.iter().map(canon).collect()),
        OwnedTerm::List { elems, tail } => OwnedTerm::List {
            elems: elems.iter().map(canon).collect(),
            tail: Box::new(canon(tail)),
        },
        other => other.clone(),
    }
}

fn run_arinsal(against: &OwnedTerm, spec: &OwnedTerm, dialect: MatchDialect) -> OwnedTerm {
    let mut heap = VecHeap::new();
    let against = from_owned(against, &mut heap).unwrap();
    let spec = from_owned(spec, &mut heap).unwrap();
    let mut out = VecHeap::new();
    let result = match_spec_test(against, spec, dialect, &mut out, &()).unwrap();
    to_owned(result).unwrap()
}

#[test]
fn match_spec_test_errors_vs_erl() {
    let Ok(erl) = RefErl::start() else {
        eprintln!("skipping OTP differential test: no reference erl");
        return;
    };
    let beam = erl.compile_named("ms_error_fixture", SPECS, &[]).unwrap();
    erl.load("ms_error_fixture", &beam).unwrap();
    let CallResult::Ok(specs) = erl.call("ms_error_fixture", "specs", &[]) else {
        panic!("specs/0 failed")
    };
    let specs = list_of(&specs);
    assert!(specs.len() > 120, "fixture has {} specs", specs.len());
    let table_against = OwnedTerm::Tuple(vec![OwnedTerm::atom("a"), OwnedTerm::Int(1)]);
    let trace_against = OwnedTerm::list(vec![OwnedTerm::atom("a"), OwnedTerm::Int(1)]);
    let mut errors = 0;
    for (index, spec) in specs.iter().enumerate() {
        for (dialect, name, against) in [
            (MatchDialect::Table, "table", &table_against),
            (MatchDialect::Trace, "trace", &trace_against),
        ] {
            let expected = erl.call(
                "erlang",
                "match_spec_test",
                &[against.clone(), spec.clone(), OwnedTerm::atom(name)],
            );
            let CallResult::Ok(expected) = expected else {
                panic!("OTP match_spec_test failed for spec {index} {spec:?}: {expected:?}");
            };
            if matches!(&expected, OwnedTerm::Tuple(items) if items[0] == OwnedTerm::atom("error"))
            {
                errors += 1;
            }
            let actual = run_arinsal(against, spec, dialect);
            similar_asserts::assert_eq!(
                canon(&actual),
                canon(&expected),
                "spec {index} ({name}): {spec:?}"
            );
        }
    }
    assert!(errors > 150, "only {errors} error cases");
}
