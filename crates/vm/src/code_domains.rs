//! Code domains: per-namespace module overlays on a node's code tables.
//!
//! Domain 0 is the base: the node's ordinary module table, the only one root uses. A non-zero
//! domain maps module names to instances of its own. A lookup chain lists the domains to probe
//! in order and always ends with the base, so a name no domain of the chain defines resolves
//! exactly as it does for root. Dynamic calls (`apply`, variable-module calls, spawn MFAs and
//! export funs) resolve through the calling process's chain (`Process::code_chain`); a process
//! without a chain is root and takes the unchanged base path.
//!
//! Modules of a non-zero domain run in the interpreter: they are never compiled by BeamAsm nor
//! published in the node's export dispatch table, so native call sites, which are keyed by MFA
//! per node, keep resolving to base instances.

use crate::process::Message;
use crate::{Process, Vm, VmError};
use arinsal_loader::Module;
use arinsal_sched::RunCtx;
use arinsal_term::{Atom, Term, TermBuilder, global_atoms};
use std::collections::HashMap;
use std::sync::Arc;

/// A code domain; [`BASE`] is the node's ordinary module table.
pub(crate) type DomainId = u32;

/// The base domain: root's module table.
pub(crate) const BASE: DomainId = 0;

/// Domains to probe in order, ending with [`BASE`]. The first one is where the owner loads.
pub(crate) type DomainChain = Arc<[DomainId]>;

/// The overlay of every non-base domain of one node, staged with its code tables.
#[derive(Clone, Default)]
pub(crate) struct Domains {
    last: DomainId,
    chains: HashMap<DomainId, DomainChain>,
    modules: HashMap<(DomainId, Atom), usize>,
}

impl Domains {
    /// Creates a domain whose chain is itself followed by the chains of `parents`.
    fn create(&mut self, parents: &[DomainId]) -> Option<DomainId> {
        let mut chain = Vec::new();
        for parent in parents {
            if *parent == BASE {
                continue;
            }
            for domain in self.chains.get(parent)?.iter() {
                if *domain != BASE && !chain.contains(domain) {
                    chain.push(*domain);
                }
            }
        }
        self.last = self.last.checked_add(1)?;
        let id = self.last;
        chain.insert(0, id);
        chain.push(BASE);
        self.chains.insert(id, chain.into());
        Some(id)
    }

    /// The chain of `domain`.
    pub(crate) fn chain(&self, domain: DomainId) -> Option<&DomainChain> {
        self.chains.get(&domain)
    }

    /// The instance of `module` in the first non-base domain of `chain` that has one.
    #[inline]
    pub(crate) fn lookup(&self, chain: &[DomainId], module: Atom) -> Option<usize> {
        if self.modules.is_empty() {
            return None;
        }
        chain
            .iter()
            .take_while(|domain| **domain != BASE)
            .find_map(|domain| self.modules.get(&(*domain, module)).copied())
    }

    /// Every domain instance of `module`.
    pub(crate) fn instances_of(&self, module: Atom) -> impl Iterator<Item = usize> + '_ {
        self.modules
            .iter()
            .filter(move |((_, name), _)| *name == module)
            .map(|(_, id)| *id)
    }

    /// Whether `chain` names only existing domains and ends with the base.
    fn valid_chain(&self, chain: &[DomainId]) -> bool {
        chain.last() == Some(&BASE)
            && chain[..chain.len() - 1]
                .iter()
                .all(|domain| *domain != BASE && self.chains.contains_key(domain))
    }
}

impl crate::load::CodeTables {
    /// The current instance of `module` seen through `chain`: its non-base domains first,
    /// then the base table. No chain is root, which reads the base table only.
    #[inline]
    pub(crate) fn module_in_chain(
        &self,
        chain: Option<&[DomainId]>,
        module: Atom,
    ) -> Option<usize> {
        if let Some(chain) = chain
            && let Some(id) = self.domains.lookup(chain, module)
        {
            return Some(id);
        }
        self.loaded.get(&module).copied()
    }
}

impl Vm {
    /// The domain instance a dynamic call of `module` from process `p` reaches, when the
    /// process has a chain and one of its non-base domains defines the module.
    #[inline]
    pub(crate) fn process_domain_module(&self, p: &Process, module: Atom) -> Option<usize> {
        let chain = p.code_chain.as_deref()?;
        self.code.domains.lookup(chain, module)
    }

    /// The domain instance a static call of `module` from an instance of `domain` reaches,
    /// through that domain's chain; `None` sends the call to the base table.
    #[inline]
    pub(crate) fn caller_domain_module(&self, domain: DomainId, module: Atom) -> Option<usize> {
        if domain == BASE {
            return None;
        }
        let chain = self.code.domains.chain(domain)?;
        self.code.domains.lookup(chain, module)
    }

    /// The current instance of `module` that process `p` sees: its chain's domains first,
    /// then the base table.
    pub(crate) fn module_for_process(&self, p: &Process, module: Atom) -> Option<usize> {
        self.code.module_in_chain(p.code_chain.as_deref(), module)
    }

    /// Creates a domain under `parents`.
    pub(crate) fn new_code_domain(&mut self, parents: &[DomainId]) -> Option<DomainId> {
        let id = self
            .code_ix
            .update_active(|tables| tables.domains.create(parents));
        self.refresh_code();
        id
    }

    /// Loads `beams` into `domain`, each as `(module, bytes)`; see [`Vm::install_in_domain`].
    pub(crate) fn load_into_domain(
        &mut self,
        domain: DomainId,
        beams: &[(Atom, Vec<u8>)],
    ) -> Result<(), (&'static str, Vec<Atom>)> {
        let mut prepared = Vec::with_capacity(beams.len());
        for (name, bytes) in beams {
            let Ok(beam) = arinsal_beam::parse(bytes) else {
                return Err(("badfile", vec![*name]));
            };
            if global_atoms().text(*name) != Some(beam.module.as_str()) {
                return Err(("badfile", vec![*name]));
            }
            let Ok(module) = self.prepare_module(&beam, Some(bytes)) else {
                return Err(("badfile", vec![*name]));
            };
            prepared.push((
                module,
                crate::process::register_requirements(&beam),
                crate::load::CodeMeta::from_beam(&beam, Some(bytes)),
            ));
        }
        self.install_in_domain(domain, prepared)
    }

    /// Makes the prepared modules current in `domain`, all or none. The modules are
    /// interpreted only.
    ///
    /// - A module whose name the domain's chain already resolves to an instance with the same
    ///   md5 (in this domain, an outer domain or the base) is skipped: the load is a no-op.
    /// - A module whose name the chain resolves to a base instance with a different md5 is
    ///   `not_allowed`: a domain does not shadow the base, except a consolidated Elixir
    ///   protocol over another one (both export `__protocol__/1`).
    /// - A module the domain already has is replaced; the replaced instance is condemned and
    ///   freed by a later purge once no process runs it. A name an outer non-base domain
    ///   defines is shadowed by this domain.
    /// - `-on_load` modules are refused (`on_load`).
    pub(crate) fn install_in_domain(
        &mut self,
        domain: DomainId,
        prepared: Vec<(Module, (usize, usize), crate::load::CodeMeta)>,
    ) -> Result<(), (&'static str, Vec<Atom>)> {
        self.refresh_code();
        let Some(chain) = self.code.domains.chain(domain).cloned() else {
            return Err(("badarg", Vec::new()));
        };
        if domain == BASE {
            return Err(("badarg", Vec::new()));
        }
        let mut seen = std::collections::HashSet::new();
        let duplicates: Vec<Atom> = prepared
            .iter()
            .map(|(module, _, _)| module.name_atom)
            .filter(|name| !seen.insert(*name))
            .collect();
        if !duplicates.is_empty() {
            return Err(("duplicated", duplicates));
        }
        let mut install = Vec::with_capacity(prepared.len());
        for (module, registers, meta) in prepared {
            let name = module.name_atom;
            if let Some(id) = self.code.module_in_chain(Some(&chain), name) {
                let visible_md5 = self
                    .code
                    .code_meta
                    .get(id)
                    .and_then(Option::as_ref)
                    .and_then(|visible| visible.md5);
                if meta.md5.is_some() && meta.md5 == visible_md5 {
                    continue;
                }
                let visible = &self.code.modules[id];
                if visible.domain == BASE && !shadows_protocol(&module, visible) {
                    return Err(("not_allowed", vec![name]));
                }
            }
            if meta.on_load.is_some() {
                return Err(("on_load", vec![name]));
            }
            install.push((module, registers, meta));
        }
        if install.is_empty() {
            return Ok(());
        }
        let staging = self.code_ix.start_staging();
        for (mut module, registers, meta) in install {
            let name = module.name_atom;
            module.domain = domain;
            staging.with(|tables| {
                tables.intern_fun_entries(&mut module);
                let id = tables.alloc_in_domain(Arc::new(module), registers, Some(meta));
                if let Some(previous) = tables.domains.modules.insert((domain, name), id) {
                    tables.condemned.push(previous);
                }
            });
        }
        drop(staging);
        self.refresh_code();
        Ok(())
    }
}

/// A consolidated Elixir protocol may shadow the base one: each project consolidates its
/// protocols over its own implementations.
fn shadows_protocol(module: &Module, base: &Module) -> bool {
    module.export_slot("__protocol__", 1).is_some() && base.export_slot("__protocol__", 1).is_some()
}

/// `arinsal_code` test and boot natives. All but `chain/1` are root only.
pub(crate) const IMPLEMENTED: &[(&str, &str, u8)] = &[
    ("arinsal_code", "chain", 1),
    ("arinsal_code", "load", 2),
    ("arinsal_code", "new_domain", 1),
    ("arinsal_code", "spawn", 4),
];

fn atom(name: &str) -> Term {
    Term::atom(global_atoms().intern(name).expect("atom table"))
}

fn badarg() -> VmError {
    VmError::Trap(crate::exceptions::Trap::error(atom("badarg")))
}

fn domain_id(term: Term) -> Option<DomainId> {
    term.as_small()
        .and_then(|value| DomainId::try_from(value).ok())
}

fn domain_list(term: Term) -> Option<Vec<DomainId>> {
    if let Some(domain) = domain_id(term) {
        return Some(vec![domain]);
    }
    crate::signals::list(term)?
        .into_iter()
        .map(domain_id)
        .collect()
}

fn require_root(process: &Process) -> Result<(), VmError> {
    if process.code_chain.is_some() {
        return Err(badarg());
    }
    Ok(())
}

/// Dispatches one `arinsal_code` native.
pub(crate) fn call(
    vm: &mut Vm,
    process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
    function: &str,
    args: &[Term],
) -> Result<Term, VmError> {
    match (function, args) {
        ("new_domain", [parents]) => {
            require_root(process)?;
            let parents = domain_list(*parents).ok_or_else(badarg)?;
            let id = vm.new_code_domain(&parents).ok_or_else(badarg)?;
            Term::small(i64::from(id)).ok_or_else(badarg)
        }
        ("load", [domain, modules]) => {
            require_root(process)?;
            let domain = domain_id(*domain).ok_or_else(badarg)?;
            let mut beams = Vec::new();
            for entry in crate::signals::list(*modules).ok_or_else(badarg)? {
                let (name, binary) = crate::natives::proc::tuple2(entry).ok_or_else(badarg)?;
                let name = name.as_atom().ok_or_else(badarg)?;
                let mut owned = arinsal_term::to_owned(binary).map_err(|_| badarg())?;
                let arinsal_etf::OwnedTerm::Binary(ref mut bytes) = owned else {
                    return Err(badarg());
                };
                let bytes = std::mem::take(bytes);
                beams.push((name, bytes));
            }
            match vm.load_into_domain(domain, &beams) {
                Ok(()) => Ok(atom("ok")),
                Err(("badarg", _)) => Err(badarg()),
                Err((reason, names)) => {
                    process.ensure(8 + 2 * names.len(), 0)?;
                    let mut builder = TermBuilder::new(&mut process.heap);
                    let names = builder
                        .list_from_iter(names.into_iter().map(Term::atom))
                        .map_err(|_| badarg())?;
                    let detail = builder
                        .tuple(&[atom(reason), names])
                        .map_err(|_| badarg())?;
                    builder
                        .tuple(&[atom("error"), detail])
                        .map_err(|_| badarg())
                }
            }
        }
        ("spawn", [chain, module, function, arguments]) => {
            require_root(process)?;
            let mut chain = domain_list(*chain).ok_or_else(badarg)?;
            if chain.last() != Some(&BASE) {
                chain.push(BASE);
            }
            vm.refresh_code();
            if !vm.code.domains.valid_chain(&chain) {
                return Err(badarg());
            }
            let chain: Option<DomainChain> = (chain.len() > 1).then(|| chain.into());
            let saved = std::mem::replace(&mut process.code_chain, chain);
            let created = crate::signals::erl_create_process(
                vm,
                process,
                ctx,
                (*module, *function, *arguments),
                crate::signals::ErlSpawnOpts {
                    link: false,
                    monitor: None,
                    min_heap: None,
                    min_bin_vheap: None,
                    fullsweep: None,
                    max_heap: None,
                    off_heap_queue: None,
                    scheduler: None,
                    priority: arinsal_sched::Priority::Normal,
                    opts: Term::NIL,
                    reply: None,
                    group_leader: None,
                    ns: None,
                },
            );
            process.code_chain = saved;
            created?.pid.to_term().ok_or_else(badarg)
        }
        ("chain", [pid]) => {
            if arinsal_sched::Pid::from_term(*pid) != process.self_pid {
                return Err(badarg());
            }
            let chain: Vec<DomainId> = process
                .code_chain
                .as_deref()
                .map_or_else(|| vec![BASE], <[DomainId]>::to_vec);
            process.ensure(2 * chain.len(), 1)?;
            TermBuilder::new(&mut process.heap)
                .list_from_iter(
                    chain
                        .into_iter()
                        .filter_map(|domain| Term::small(i64::from(domain))),
                )
                .map_err(|_| badarg())
        }
        _ => Err(badarg()),
    }
}

impl Vm {
    /// The domain instance and entry of local fun `entry`: its identity (index and uniq)
    /// names one module body, so any live domain instance with it runs the same code.
    #[cold]
    pub(crate) fn domain_local_fun(
        &self,
        entry: &arinsal_term::FunEntry,
    ) -> Option<(usize, usize)> {
        self.code.domains.instances_of(entry.module).find_map(|id| {
            self.code.modules[id]
                .funs
                .iter()
                .find(|slot| {
                    slot.entry.index == entry.index
                        && slot.entry.uniq == entry.uniq
                        && slot.entry.arity == entry.arity
                })
                .map(|slot| (id, slot.target))
        })
    }
}
