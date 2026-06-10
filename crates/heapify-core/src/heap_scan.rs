use crate::allocator_sources::{AllocatorSourceSummary, AllocatorWarning, AllocatorWarningKind};
use crate::glibc::{
    FastbinBinValidation, FastbinValidationStatus, FastbinsSnapshot, GlibcHeapSnapshot,
    GlibcProfile, LargebinBinValidation, LargebinValidationStatus, LargebinsSnapshot,
    SmallbinBinValidation, SmallbinValidationStatus, SmallbinsSnapshot, UnsortedBinSnapshot,
    UnsortedBinValidation, UnsortedBinValidationStatus,
};
use crate::tcache::ObservedTcacheTracker;
use crate::tracker::{HeapTracker, ObservedChunkState};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeapScanFindingSeverity {
    Info,
    Warning,
    Suspicious,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeapScanStatus {
    Plausible,
    Incomplete,
    Suspicious,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeapScanFinding {
    pub severity: HeapScanFindingSeverity,
    pub kind: String,
    pub chunk_addr: Option<u64>,
    pub user_addr: Option<u64>,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeapScanReport {
    pub chunks_walked: usize,
    pub allocated_observed: usize,
    pub freed_observed: usize,
    pub unknown_observed: usize,
    pub allocator_source_chunks: usize,
    pub warning_count: usize,
    pub suspicious_count: usize,
    pub top_validated: Option<bool>,
    pub heap_snapshot_truncated: bool,
    pub status: HeapScanStatus,
    pub findings: Vec<HeapScanFinding>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeapScanSourceNode {
    pub source_kind: String,
    pub source_label: String,
    pub chunk_addr: u64,
    pub user_addr: u64,
    pub expected_size: Option<u64>,
    pub actual_size: Option<u64>,
    pub chain_index: Option<usize>,
}

pub struct HeapScanInputs<'a> {
    pub heap_snapshot: Option<&'a GlibcHeapSnapshot>,
    pub heap_tracker: &'a HeapTracker,
    pub allocator_summary: Option<&'a AllocatorSourceSummary>,
    pub allocator_warnings: &'a [AllocatorWarning],
    pub main_arena_top_validated: Option<bool>,
    pub profile: GlibcProfile,
    pub tcache: Option<&'a ObservedTcacheTracker>,
    pub fastbins: Option<&'a FastbinsSnapshot>,
    pub unsorted: Option<&'a UnsortedBinSnapshot>,
    pub smallbins: Option<&'a SmallbinsSnapshot>,
    pub largebins: Option<&'a LargebinsSnapshot>,
    pub max_tcache_chain: usize,
    pub fastbin_validation_statuses: &'a [FastbinBinValidation],
    pub unsorted_validation_status: Option<&'a UnsortedBinValidation>,
    pub smallbin_validation_statuses: &'a [SmallbinBinValidation],
    pub largebin_validation_statuses: &'a [LargebinBinValidation],
}

pub fn heap_scan_finding_severity_str(severity: HeapScanFindingSeverity) -> &'static str {
    match severity {
        HeapScanFindingSeverity::Info => "info",
        HeapScanFindingSeverity::Warning => "warning",
        HeapScanFindingSeverity::Suspicious => "suspicious",
    }
}

pub fn heap_scan_status_str(status: HeapScanStatus) -> &'static str {
    match status {
        HeapScanStatus::Plausible => "plausible",
        HeapScanStatus::Incomplete => "incomplete",
        HeapScanStatus::Suspicious => "suspicious",
    }
}

pub fn collect_heap_scan_source_nodes(
    tcache: Option<&ObservedTcacheTracker>,
    fastbins: Option<&FastbinsSnapshot>,
    unsorted: Option<&UnsortedBinSnapshot>,
    smallbins: Option<&SmallbinsSnapshot>,
    largebins: Option<&LargebinsSnapshot>,
    heap_snapshot: Option<&GlibcHeapSnapshot>,
    profile: GlibcProfile,
    max_tcache_chain: usize,
) -> Vec<HeapScanSourceNode> {
    let mut nodes = Vec::new();

    if let Some(tcache) = tcache {
        for chain in tcache.chains(max_tcache_chain) {
            for (index, user_addr) in chain.entries.iter().copied().enumerate() {
                let Some(chunk_addr) = user_addr.checked_sub(profile.chunk_header_size) else {
                    continue;
                };
                nodes.push(HeapScanSourceNode {
                    source_kind: "tcache_candidate".to_string(),
                    source_label: format!("tcache_candidate[0x{:x}]", chain.chunk_size),
                    chunk_addr,
                    user_addr,
                    expected_size: Some(chain.chunk_size),
                    actual_size: heap_snapshot
                        .and_then(|snapshot| {
                            snapshot
                                .chunks
                                .iter()
                                .find(|chunk| chunk.chunk_addr == chunk_addr)
                        })
                        .map(|chunk| chunk.size),
                    chain_index: Some(index),
                });
            }
        }
    }

    if let Some(fastbins) = fastbins {
        for chain in &fastbins.chains {
            for (index, node) in chain.nodes.iter().enumerate() {
                nodes.push(HeapScanSourceNode {
                    source_kind: "fastbin".to_string(),
                    source_label: format!("fastbin[0x{:x}]", chain.chunk_size),
                    chunk_addr: node.chunk_addr,
                    user_addr: node.user_addr,
                    expected_size: Some(chain.chunk_size),
                    actual_size: node.chunk_size,
                    chain_index: Some(index),
                });
            }
        }
    }

    if let Some(chain) = unsorted.and_then(|snapshot| snapshot.chain.as_ref()) {
        for (index, node) in chain.nodes.iter().enumerate() {
            nodes.push(HeapScanSourceNode {
                source_kind: "unsorted".to_string(),
                source_label: "unsorted".to_string(),
                chunk_addr: node.chunk_addr,
                user_addr: node.user_addr,
                expected_size: None,
                actual_size: node.chunk_size,
                chain_index: Some(index),
            });
        }
    }

    if let Some(smallbins) = smallbins {
        for chain in &smallbins.chains {
            for (index, node) in chain.nodes.iter().enumerate() {
                nodes.push(HeapScanSourceNode {
                    source_kind: "smallbin".to_string(),
                    source_label: format!("smallbin[0x{:x}]", chain.expected_chunk_size),
                    chunk_addr: node.chunk_addr,
                    user_addr: node.user_addr,
                    expected_size: Some(chain.expected_chunk_size),
                    actual_size: node.chunk_size,
                    chain_index: Some(index),
                });
            }
        }
    }

    if let Some(largebins) = largebins {
        for chain in &largebins.chains {
            for (index, node) in chain.nodes.iter().enumerate() {
                nodes.push(HeapScanSourceNode {
                    source_kind: "largebin".to_string(),
                    source_label: "largebin".to_string(),
                    chunk_addr: node.chunk_addr,
                    user_addr: node.user_addr,
                    expected_size: None,
                    actual_size: node.chunk_size,
                    chain_index: Some(index),
                });
            }
        }
    }

    nodes
}

pub fn build_heap_scan_report(inputs: HeapScanInputs<'_>) -> HeapScanReport {
    let mut allocated_observed = 0;
    let mut freed_observed = 0;

    if let Some(snapshot) = inputs.heap_snapshot {
        for chunk in &snapshot.chunks {
            match inputs.heap_tracker.state_for_user_addr(chunk.user_addr) {
                Some(ObservedChunkState::Allocated) => allocated_observed += 1,
                Some(ObservedChunkState::Freed) => freed_observed += 1,
                None => {}
            }
        }
    }

    let chunks_walked = inputs
        .heap_snapshot
        .map(|snapshot| snapshot.chunks.len())
        .unwrap_or_default();
    let unknown_observed = chunks_walked.saturating_sub(allocated_observed + freed_observed);
    let allocator_source_chunks = inputs
        .allocator_summary
        .map(|summary| summary.total_free_list_chunks)
        .unwrap_or_default();
    let heap_snapshot_truncated = inputs
        .heap_snapshot
        .map(|snapshot| snapshot.truncated)
        .unwrap_or_default();

    let source_nodes = collect_heap_scan_source_nodes(
        inputs.tcache,
        inputs.fastbins,
        inputs.unsorted,
        inputs.smallbins,
        inputs.largebins,
        inputs.heap_snapshot,
        inputs.profile,
        inputs.max_tcache_chain,
    );

    let mut findings = Vec::new();
    if inputs.heap_snapshot.is_none() {
        push_finding(
            &mut findings,
            HeapScanFinding {
                severity: HeapScanFindingSeverity::Warning,
                kind: "heap_snapshot_unavailable".to_string(),
                chunk_addr: None,
                user_addr: None,
                message: "heap snapshot unavailable; scan uses summary-only evidence".to_string(),
            },
        );
    } else if heap_snapshot_truncated {
        push_finding(
            &mut findings,
            HeapScanFinding {
                severity: HeapScanFindingSeverity::Warning,
                kind: "heap_snapshot_truncated".to_string(),
                chunk_addr: None,
                user_addr: None,
                message: "heap snapshot walk was truncated".to_string(),
            },
        );
    }

    for warning in inputs.allocator_warnings {
        let (severity, kind) = allocator_warning_scan_finding(warning.kind);
        push_finding(
            &mut findings,
            HeapScanFinding {
                severity,
                kind: kind.to_string(),
                chunk_addr: Some(warning.chunk_addr),
                user_addr: Some(warning.user_addr),
                message: warning.message.clone(),
            },
        );
    }

    add_source_node_findings(
        &mut findings,
        &source_nodes,
        inputs.heap_tracker,
        inputs.profile,
    );
    add_chain_findings(
        &mut findings,
        inputs.fastbins,
        inputs.unsorted,
        inputs.smallbins,
        inputs.largebins,
    );

    if inputs.main_arena_top_validated == Some(false) {
        push_finding(
            &mut findings,
            HeapScanFinding {
                severity: HeapScanFindingSeverity::Suspicious,
                kind: "main_arena_top_not_validated".to_string(),
                chunk_addr: None,
                user_addr: None,
                message: "main_arena.top did not validate against the walked heap".to_string(),
            },
        );
    }

    add_fastbin_validation_findings(&mut findings, inputs.fastbin_validation_statuses);
    add_unsorted_validation_finding(&mut findings, inputs.unsorted_validation_status);
    add_smallbin_validation_findings(&mut findings, inputs.smallbin_validation_statuses);
    add_largebin_validation_findings(&mut findings, inputs.largebin_validation_statuses);

    let suspicious_count = findings
        .iter()
        .filter(|finding| finding.severity == HeapScanFindingSeverity::Suspicious)
        .count();
    let has_warning = findings
        .iter()
        .any(|finding| finding.severity == HeapScanFindingSeverity::Warning);
    let status = if suspicious_count > 0 {
        HeapScanStatus::Suspicious
    } else if has_warning || inputs.heap_snapshot.is_none() || heap_snapshot_truncated {
        HeapScanStatus::Incomplete
    } else {
        HeapScanStatus::Plausible
    };

    HeapScanReport {
        chunks_walked,
        allocated_observed,
        freed_observed,
        unknown_observed,
        allocator_source_chunks,
        warning_count: inputs.allocator_warnings.len(),
        suspicious_count,
        top_validated: inputs.main_arena_top_validated,
        heap_snapshot_truncated,
        status,
        findings,
    }
}

fn allocator_warning_scan_finding(
    kind: AllocatorWarningKind,
) -> (HeapScanFindingSeverity, &'static str) {
    match kind {
        AllocatorWarningKind::ConflictingAllocatorSources => (
            HeapScanFindingSeverity::Suspicious,
            "allocator_source_conflict",
        ),
        AllocatorWarningKind::AllocatorSourceButTrackerAllocated => (
            HeapScanFindingSeverity::Suspicious,
            "allocator_source_allocated",
        ),
        AllocatorWarningKind::SizeMismatch => (
            HeapScanFindingSeverity::Suspicious,
            "free_list_size_mismatch",
        ),
    }
}

fn add_source_node_findings(
    findings: &mut Vec<HeapScanFinding>,
    nodes: &[HeapScanSourceNode],
    heap_tracker: &HeapTracker,
    profile: GlibcProfile,
) {
    for node in nodes {
        if heap_tracker.state_for_user_addr(node.user_addr) == Some(ObservedChunkState::Allocated) {
            if has_finding_identity(
                findings,
                "allocator_source_allocated",
                Some(node.chunk_addr),
                Some(node.user_addr),
            ) {
                continue;
            }
            push_finding(
                findings,
                HeapScanFinding {
                    severity: HeapScanFindingSeverity::Suspicious,
                    kind: "allocator_source_allocated".to_string(),
                    chunk_addr: Some(node.chunk_addr),
                    user_addr: Some(node.user_addr),
                    message: format!(
                        "{} contains chunk whose tracker state is allocated",
                        node.source_label
                    ),
                },
            );
        }

        if let (Some(expected), Some(actual)) = (node.expected_size, node.actual_size) {
            if expected != actual {
                push_finding(
                    findings,
                    HeapScanFinding {
                        severity: HeapScanFindingSeverity::Suspicious,
                        kind: "free_list_size_mismatch".to_string(),
                        chunk_addr: Some(node.chunk_addr),
                        user_addr: Some(node.user_addr),
                        message: format!(
                            "{} expected size 0x{expected:x} but chunk has size 0x{actual:x}",
                            node.source_label
                        ),
                    },
                );
            }
        }

        if node.source_kind == "largebin" {
            if let Some(actual) = node.actual_size {
                if actual < profile.min_chunk_size || !profile.is_aligned_chunk_size(actual) {
                    push_finding(
                        findings,
                        HeapScanFinding {
                            severity: HeapScanFindingSeverity::Suspicious,
                            kind: "free_list_size_mismatch".to_string(),
                            chunk_addr: Some(node.chunk_addr),
                            user_addr: Some(node.user_addr),
                            message: format!(
                                "{} chunk has invalid size 0x{actual:x}",
                                node.source_label
                            ),
                        },
                    );
                }
            }
        }
    }
}

fn add_chain_findings(
    findings: &mut Vec<HeapScanFinding>,
    fastbins: Option<&FastbinsSnapshot>,
    unsorted: Option<&UnsortedBinSnapshot>,
    smallbins: Option<&SmallbinsSnapshot>,
    largebins: Option<&LargebinsSnapshot>,
) {
    if let Some(fastbins) = fastbins {
        for chain in &fastbins.chains {
            let label = format!("fastbin[0x{:x}]", chain.chunk_size);
            if chain.cycle_detected {
                push_finding(findings, cycle_finding(&label, chain.head));
            }
            if chain.stopped_on_unknown_next {
                push_finding(findings, outside_heap_finding(&label, chain.head));
            }
            if fastbins
                .heads
                .iter()
                .find(|head| head.index == chain.index)
                .is_some_and(|head| head.head != 0 && !head.points_into_heap)
            {
                push_finding(findings, outside_heap_finding(&label, chain.head));
            }
        }
    }

    if let Some(chain) = unsorted.and_then(|snapshot| snapshot.chain.as_ref()) {
        if chain.cycle_detected {
            push_finding(findings, cycle_finding("unsorted", chain.head));
        }
        if chain.stopped_on_unknown_next {
            push_finding(findings, outside_heap_finding("unsorted", chain.head));
        }
    }

    if let Some(smallbins) = smallbins {
        for chain in &smallbins.chains {
            let label = format!("smallbin[0x{:x}]", chain.expected_chunk_size);
            if chain.cycle_detected {
                push_finding(findings, cycle_finding(&label, chain.head));
            }
            if chain.stopped_on_unknown_next {
                push_finding(findings, outside_heap_finding(&label, chain.head));
            }
        }
    }

    if let Some(largebins) = largebins {
        for chain in &largebins.chains {
            if chain.cycle_detected {
                push_finding(findings, cycle_finding("largebin", chain.head));
            }
            if chain.stopped_on_unknown_next {
                push_finding(findings, outside_heap_finding("largebin", chain.head));
            }
        }
    }
}

fn cycle_finding(source_label: &str, chunk_addr: u64) -> HeapScanFinding {
    HeapScanFinding {
        severity: HeapScanFindingSeverity::Suspicious,
        kind: "free_list_cycle".to_string(),
        chunk_addr: (chunk_addr != 0).then_some(chunk_addr),
        user_addr: None,
        message: format!("{source_label} chain contains a cycle"),
    }
}

fn outside_heap_finding(source_label: &str, chunk_addr: u64) -> HeapScanFinding {
    HeapScanFinding {
        severity: HeapScanFindingSeverity::Suspicious,
        kind: "free_list_node_outside_heap".to_string(),
        chunk_addr: (chunk_addr != 0).then_some(chunk_addr),
        user_addr: None,
        message: format!("{source_label} chain references a node outside the walked heap"),
    }
}

fn push_finding(findings: &mut Vec<HeapScanFinding>, finding: HeapScanFinding) {
    let duplicate = findings.iter().any(|existing| {
        existing.kind == finding.kind
            && existing.chunk_addr == finding.chunk_addr
            && existing.user_addr == finding.user_addr
            && existing.message == finding.message
    });
    if !duplicate {
        findings.push(finding);
    }
}

fn has_finding_identity(
    findings: &[HeapScanFinding],
    kind: &str,
    chunk_addr: Option<u64>,
    user_addr: Option<u64>,
) -> bool {
    findings.iter().any(|finding| {
        finding.kind == kind && finding.chunk_addr == chunk_addr && finding.user_addr == user_addr
    })
}

fn add_fastbin_validation_findings(
    findings: &mut Vec<HeapScanFinding>,
    validations: &[FastbinBinValidation],
) {
    for validation in validations {
        let (severity, status, message) = match validation.status {
            FastbinValidationStatus::Plausible => continue,
            FastbinValidationStatus::Incomplete => (
                HeapScanFindingSeverity::Warning,
                "incomplete",
                "fastbin validation is incomplete",
            ),
            FastbinValidationStatus::Suspicious => (
                HeapScanFindingSeverity::Suspicious,
                "suspicious",
                "fastbin validation is suspicious",
            ),
        };
        push_finding(
            findings,
            HeapScanFinding {
                severity,
                kind: format!("bin_validation_{status}"),
                chunk_addr: (validation.head != 0).then_some(validation.head),
                user_addr: None,
                message: format!("{message} for index {}", validation.index),
            },
        );
    }
}

fn add_unsorted_validation_finding(
    findings: &mut Vec<HeapScanFinding>,
    validation: Option<&UnsortedBinValidation>,
) {
    let Some(validation) = validation else {
        return;
    };
    let (severity, status, message) = match validation.status {
        UnsortedBinValidationStatus::Plausible => return,
        UnsortedBinValidationStatus::Incomplete => (
            HeapScanFindingSeverity::Warning,
            "incomplete",
            "unsorted bin validation is incomplete",
        ),
        UnsortedBinValidationStatus::Suspicious => (
            HeapScanFindingSeverity::Suspicious,
            "suspicious",
            "unsorted bin validation is suspicious",
        ),
    };
    push_finding(
        findings,
        HeapScanFinding {
            severity,
            kind: format!("bin_validation_{status}"),
            chunk_addr: None,
            user_addr: None,
            message: message.to_string(),
        },
    );
}

fn add_smallbin_validation_findings(
    findings: &mut Vec<HeapScanFinding>,
    validations: &[SmallbinBinValidation],
) {
    for validation in validations {
        let (severity, status, message) = match validation.status {
            SmallbinValidationStatus::Plausible => continue,
            SmallbinValidationStatus::Incomplete => (
                HeapScanFindingSeverity::Warning,
                "incomplete",
                "smallbin validation is incomplete",
            ),
            SmallbinValidationStatus::Suspicious => (
                HeapScanFindingSeverity::Suspicious,
                "suspicious",
                "smallbin validation is suspicious",
            ),
        };
        push_finding(
            findings,
            HeapScanFinding {
                severity,
                kind: format!("bin_validation_{status}"),
                chunk_addr: (validation.head != 0).then_some(validation.head),
                user_addr: None,
                message: format!("{message} for glibc bin {}", validation.glibc_bin_index),
            },
        );
    }
}

fn add_largebin_validation_findings(
    findings: &mut Vec<HeapScanFinding>,
    validations: &[LargebinBinValidation],
) {
    for validation in validations {
        let (severity, status, message) = match validation.status {
            LargebinValidationStatus::Plausible => continue,
            LargebinValidationStatus::Incomplete => (
                HeapScanFindingSeverity::Warning,
                "incomplete",
                "largebin validation is incomplete",
            ),
            LargebinValidationStatus::Suspicious => (
                HeapScanFindingSeverity::Suspicious,
                "suspicious",
                "largebin validation is suspicious",
            ),
        };
        push_finding(
            findings,
            HeapScanFinding {
                severity,
                kind: format!("bin_validation_{status}"),
                chunk_addr: (validation.head != 0).then_some(validation.head),
                user_addr: None,
                message: format!("{message} for glibc bin {}", validation.glibc_bin_index),
            },
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::allocator_sources::{AllocatorSourceSummary, AllocatorWarning};
    use crate::glibc::{
        ChunkFlags, FastbinChain, FastbinHead, FastbinNode, FastbinsSnapshot, GlibcChunkHeader,
        LargebinChain, LargebinNode, LargebinsSnapshot, SmallbinChain, SmallbinNode,
        SmallbinsSnapshot, UnsortedBinChain, UnsortedBinNode, UnsortedBinSnapshot,
        GLIBC_X86_64_MODERN,
    };
    use crate::tcache::ObservedTcacheTracker;

    #[test]
    fn no_heap_snapshot_report_is_incomplete() {
        let tracker = HeapTracker::new();
        let report = build_heap_scan_report(inputs(None, &tracker, None, &[]));

        assert_eq!(report.status, HeapScanStatus::Incomplete);
        assert_eq!(report.chunks_walked, 0);
        assert_eq!(report.findings[0].kind, "heap_snapshot_unavailable");
    }

    #[test]
    fn complete_snapshot_with_no_warnings_is_plausible() {
        let mut tracker = HeapTracker::new();
        tracker.observe_malloc(1, 8, 0x1010, Some(0x20));
        let snapshot = snapshot(false);

        let report = build_heap_scan_report(inputs(Some(&snapshot), &tracker, None, &[]));

        assert_eq!(report.status, HeapScanStatus::Plausible);
        assert_eq!(report.chunks_walked, 1);
        assert_eq!(report.allocated_observed, 1);
    }

    #[test]
    fn truncated_snapshot_is_incomplete() {
        let tracker = HeapTracker::new();
        let snapshot = snapshot(true);

        let report = build_heap_scan_report(inputs(Some(&snapshot), &tracker, None, &[]));

        assert_eq!(report.status, HeapScanStatus::Incomplete);
        assert_eq!(report.findings[0].kind, "heap_snapshot_truncated");
    }

    #[test]
    fn allocator_warning_produces_suspicious_report() {
        let tracker = HeapTracker::new();
        let snapshot = snapshot(false);
        let warnings = vec![AllocatorWarning {
            kind: AllocatorWarningKind::ConflictingAllocatorSources,
            chunk_addr: 0x1000,
            user_addr: 0x1010,
            sources: Vec::new(),
            message: "conflict".to_string(),
        }];

        let report = build_heap_scan_report(inputs(Some(&snapshot), &tracker, None, &warnings));

        assert_eq!(report.status, HeapScanStatus::Suspicious);
        assert_eq!(report.suspicious_count, 1);
        assert_eq!(report.findings[0].chunk_addr, Some(0x1000));
        assert_eq!(report.findings[0].kind, "allocator_source_conflict");
    }

    #[test]
    fn top_validated_false_produces_suspicious_finding() {
        let tracker = HeapTracker::new();
        let snapshot = snapshot(false);

        let report = build_heap_scan_report(HeapScanInputs {
            main_arena_top_validated: Some(false),
            ..inputs(Some(&snapshot), &tracker, None, &[])
        });

        assert_eq!(report.status, HeapScanStatus::Suspicious);
        assert!(report
            .findings
            .iter()
            .any(|finding| finding.kind == "main_arena_top_not_validated"));
    }

    #[test]
    fn string_helpers_are_stable() {
        assert_eq!(
            heap_scan_finding_severity_str(HeapScanFindingSeverity::Info),
            "info"
        );
        assert_eq!(
            heap_scan_finding_severity_str(HeapScanFindingSeverity::Warning),
            "warning"
        );
        assert_eq!(
            heap_scan_finding_severity_str(HeapScanFindingSeverity::Suspicious),
            "suspicious"
        );
        assert_eq!(heap_scan_status_str(HeapScanStatus::Plausible), "plausible");
        assert_eq!(
            heap_scan_status_str(HeapScanStatus::Incomplete),
            "incomplete"
        );
        assert_eq!(
            heap_scan_status_str(HeapScanStatus::Suspicious),
            "suspicious"
        );
    }

    #[test]
    fn source_node_collection_covers_allocator_sources() {
        let mut tcache = ObservedTcacheTracker::new();
        tcache.observe_free(0x1010, 0x20, 0);
        let fastbins = fastbins_snapshot(false, false, Some(0x30));
        let unsorted = unsorted_snapshot(false, false);
        let smallbins = smallbins_snapshot(false, false, Some(0x40));
        let largebins = largebins_snapshot(false, false, Some(0x80));
        let snapshot = snapshot(false);

        let nodes = collect_heap_scan_source_nodes(
            Some(&tcache),
            Some(&fastbins),
            Some(&unsorted),
            Some(&smallbins),
            Some(&largebins),
            Some(&snapshot),
            GLIBC_X86_64_MODERN,
            8,
        );

        assert!(nodes.iter().any(|node| {
            node.source_kind == "tcache_candidate"
                && node.source_label == "tcache_candidate[0x20]"
                && node.chunk_addr == 0x1000
                && node.actual_size == Some(0x20)
        }));
        assert!(nodes
            .iter()
            .any(|node| node.source_kind == "fastbin" && node.expected_size == Some(0x30)));
        assert!(nodes
            .iter()
            .any(|node| node.source_kind == "unsorted" && node.expected_size.is_none()));
        assert!(nodes
            .iter()
            .any(|node| node.source_kind == "smallbin" && node.expected_size == Some(0x40)));
        assert!(nodes
            .iter()
            .any(|node| node.source_kind == "largebin" && node.actual_size == Some(0x80)));
    }

    #[test]
    fn size_mismatch_produces_suspicious_finding() {
        let tracker = HeapTracker::new();
        let snapshot = snapshot(false);
        let fastbins = fastbins_snapshot(false, false, Some(0x40));

        let report = build_heap_scan_report(HeapScanInputs {
            fastbins: Some(&fastbins),
            ..inputs(Some(&snapshot), &tracker, None, &[])
        });

        assert_eq!(report.status, HeapScanStatus::Suspicious);
        assert!(report.findings.iter().any(|finding| {
            finding.kind == "free_list_size_mismatch"
                && finding.message.contains("fastbin[0x30] expected size 0x30")
        }));
    }

    #[test]
    fn tracker_allocated_source_node_produces_suspicious_finding() {
        let mut tracker = HeapTracker::new();
        tracker.observe_malloc(1, 8, 0x1010, Some(0x20));
        let snapshot = snapshot(false);
        let mut tcache = ObservedTcacheTracker::new();
        tcache.observe_free(0x1010, 0x20, 0);

        let report = build_heap_scan_report(HeapScanInputs {
            tcache: Some(&tcache),
            ..inputs(Some(&snapshot), &tracker, None, &[])
        });

        assert_eq!(report.status, HeapScanStatus::Suspicious);
        assert!(report
            .findings
            .iter()
            .any(|finding| finding.kind == "allocator_source_allocated"));
    }

    #[test]
    fn cycles_in_source_chains_produce_suspicious_findings() {
        let tracker = HeapTracker::new();
        let snapshot = snapshot(false);
        let fastbins = fastbins_snapshot(true, false, Some(0x30));
        let unsorted = unsorted_snapshot(true, false);
        let smallbins = smallbins_snapshot(true, false, Some(0x40));
        let largebins = largebins_snapshot(true, false, Some(0x80));

        let report = build_heap_scan_report(HeapScanInputs {
            fastbins: Some(&fastbins),
            unsorted: Some(&unsorted),
            smallbins: Some(&smallbins),
            largebins: Some(&largebins),
            ..inputs(Some(&snapshot), &tracker, None, &[])
        });

        assert_eq!(report.status, HeapScanStatus::Suspicious);
        assert_eq!(
            report
                .findings
                .iter()
                .filter(|finding| finding.kind == "free_list_cycle")
                .count(),
            4
        );
    }

    #[test]
    fn stopped_unknown_next_produces_outside_heap_finding() {
        let tracker = HeapTracker::new();
        let snapshot = snapshot(false);
        let fastbins = fastbins_snapshot(false, true, Some(0x30));

        let report = build_heap_scan_report(HeapScanInputs {
            fastbins: Some(&fastbins),
            ..inputs(Some(&snapshot), &tracker, None, &[])
        });

        assert!(report
            .findings
            .iter()
            .any(|finding| finding.kind == "free_list_node_outside_heap"));
    }

    #[test]
    fn allocator_source_allocated_warning_dedups_direct_check() {
        let mut tracker = HeapTracker::new();
        tracker.observe_malloc(1, 8, 0x1010, Some(0x20));
        let snapshot = snapshot(false);
        let mut tcache = ObservedTcacheTracker::new();
        tcache.observe_free(0x1010, 0x20, 0);
        let warnings = vec![AllocatorWarning {
            kind: AllocatorWarningKind::AllocatorSourceButTrackerAllocated,
            chunk_addr: 0x1000,
            user_addr: 0x1010,
            sources: Vec::new(),
            message: "chunk appears in allocator source but tracker state is allocated".to_string(),
        }];

        let report = build_heap_scan_report(HeapScanInputs {
            tcache: Some(&tcache),
            ..inputs(Some(&snapshot), &tracker, None, &warnings)
        });

        assert_eq!(
            report
                .findings
                .iter()
                .filter(|finding| finding.kind == "allocator_source_allocated")
                .count(),
            1
        );
    }

    fn inputs<'a>(
        heap_snapshot: Option<&'a GlibcHeapSnapshot>,
        heap_tracker: &'a HeapTracker,
        allocator_summary: Option<&'a AllocatorSourceSummary>,
        allocator_warnings: &'a [AllocatorWarning],
    ) -> HeapScanInputs<'a> {
        HeapScanInputs {
            heap_snapshot,
            heap_tracker,
            allocator_summary,
            allocator_warnings,
            main_arena_top_validated: None,
            profile: GLIBC_X86_64_MODERN,
            tcache: None,
            fastbins: None,
            unsorted: None,
            smallbins: None,
            largebins: None,
            max_tcache_chain: 32,
            fastbin_validation_statuses: &[],
            unsorted_validation_status: None,
            smallbin_validation_statuses: &[],
            largebin_validation_statuses: &[],
        }
    }

    fn snapshot(truncated: bool) -> GlibcHeapSnapshot {
        GlibcHeapSnapshot {
            heap_start: 0x1000,
            heap_end: 0x2000,
            chunks: vec![GlibcChunkHeader {
                chunk_addr: 0x1000,
                user_addr: 0x1010,
                prev_size: 0,
                size_raw: 0x21,
                size: 0x20,
                flags: ChunkFlags {
                    prev_inuse: true,
                    is_mmapped: false,
                    non_main_arena: false,
                },
            }],
            truncated,
        }
    }

    fn fastbins_snapshot(
        cycle_detected: bool,
        stopped_on_unknown_next: bool,
        node_size: Option<u64>,
    ) -> FastbinsSnapshot {
        FastbinsSnapshot {
            arena_addr: 0x7000,
            heads: vec![FastbinHead {
                index: 1,
                chunk_size: 0x30,
                field_offset: 0x18,
                head: 0x1100,
                points_into_heap: true,
                matches_heap_chunk: true,
                known_freed: Some(true),
            }],
            chains: vec![FastbinChain {
                index: 1,
                chunk_size: 0x30,
                head: 0x1100,
                nodes: vec![FastbinNode {
                    chunk_addr: 0x1100,
                    user_addr: 0x1110,
                    encoded_next: 0,
                    decoded_next: 0,
                    chunk_size: node_size,
                    matches_heap_chunk: true,
                    known_freed: Some(true),
                }],
                truncated: false,
                stopped_on_unknown_next,
                cycle_detected,
            }],
        }
    }

    fn unsorted_snapshot(
        cycle_detected: bool,
        stopped_on_unknown_next: bool,
    ) -> UnsortedBinSnapshot {
        UnsortedBinSnapshot {
            arena_addr: 0x7000,
            field_offset: 0x70,
            fd: 0x1200,
            bk: 0x1200,
            fd_points_into_heap: true,
            bk_points_into_heap: true,
            fd_matches_heap_chunk: true,
            bk_matches_heap_chunk: true,
            fd_known_freed: Some(true),
            bk_known_freed: Some(true),
            chain: Some(UnsortedBinChain {
                sentinel_addr: 0x7070,
                head: 0x1200,
                tail: 0x1200,
                nodes: vec![UnsortedBinNode {
                    chunk_addr: 0x1200,
                    user_addr: 0x1210,
                    fd: 0x7070,
                    bk: 0x7070,
                    chunk_size: Some(0x50),
                    matches_heap_chunk: true,
                    known_freed: Some(true),
                    fd_points_to_sentinel: true,
                    bk_points_to_sentinel: true,
                }],
                empty: false,
                truncated: false,
                stopped_on_unknown_next,
                cycle_detected,
                fd_bk_consistent: true,
            }),
        }
    }

    fn smallbins_snapshot(
        cycle_detected: bool,
        stopped_on_unknown_next: bool,
        node_size: Option<u64>,
    ) -> SmallbinsSnapshot {
        SmallbinsSnapshot {
            arena_addr: 0x7000,
            bins_offset: 0x70,
            chains: vec![SmallbinChain {
                regular_index: 2,
                glibc_bin_index: 3,
                expected_chunk_size: 0x40,
                sentinel_addr: 0x7080,
                head: 0x1300,
                tail: 0x1300,
                nodes: vec![SmallbinNode {
                    chunk_addr: 0x1300,
                    user_addr: 0x1310,
                    fd: 0x7080,
                    bk: 0x7080,
                    chunk_size: node_size,
                    matches_heap_chunk: true,
                    known_freed: Some(true),
                    fd_points_to_sentinel: true,
                    bk_points_to_sentinel: true,
                }],
                empty: false,
                truncated: false,
                stopped_on_unknown_next,
                cycle_detected,
                fd_bk_consistent: true,
            }],
        }
    }

    fn largebins_snapshot(
        cycle_detected: bool,
        stopped_on_unknown_next: bool,
        node_size: Option<u64>,
    ) -> LargebinsSnapshot {
        LargebinsSnapshot {
            arena_addr: 0x7000,
            bins_offset: 0x70,
            chains: vec![LargebinChain {
                regular_index: 64,
                glibc_bin_index: 65,
                sentinel_addr: 0x7090,
                head: 0x1400,
                tail: 0x1400,
                nodes: vec![LargebinNode {
                    chunk_addr: 0x1400,
                    user_addr: 0x1410,
                    fd: 0x7090,
                    bk: 0x7090,
                    fd_nextsize: 0,
                    bk_nextsize: 0,
                    chunk_size: node_size,
                    matches_heap_chunk: true,
                    known_freed: Some(true),
                    fd_points_to_sentinel: true,
                    bk_points_to_sentinel: true,
                    fd_nextsize_points_into_heap: false,
                    bk_nextsize_points_into_heap: false,
                    fd_nextsize_points_into_arena: false,
                    bk_nextsize_points_into_arena: false,
                }],
                empty: false,
                truncated: false,
                stopped_on_unknown_next,
                cycle_detected,
                fd_bk_consistent: true,
            }],
        }
    }
}
