//! Snapshot → spaces, worktree grouping, and git status.
//!
//! [`collect_spaces`] turns one `session.snapshot` into [`Space`]s (recording
//! each space's cwd and classifying panes into agent / spare / pseudo buckets).
//! [`group_worktree_families`] tags worktree-child
//! workspaces with their parent so [`snapshot`] can drop them — worktree children
//! render as single-row indented entries in the sidebar with no room for a status
//! row, so surfacing status on them is wasted. Unlike the cpu/ram plugin, nothing
//! is summed across the family: each work tree has its own status, and the child's
//! own top-level card (if any) is where it would show.

use std::collections::{HashMap, HashSet};

use crate::git;
use crate::herdr::Herdr;
use crate::model::{PaneInfo, Space, WorkspaceInfo};

/// Pseudo-agent label marking our agents-panel entries (agents-panel mode) and
/// used to recognise / clean them up in sidebar mode.
pub const PSEUDO_AGENT: &str = "git";

/// Enumerate spaces and classify each space's panes into agent / spare / pseudo
/// buckets, recording the first pane's cwd (where git will run).
///
/// One `session.snapshot`: every workspace and every pane in a single atomic
/// read, with panes regrouped by their `workspace_id`. That ordering is the same
/// one `pane.list` reports, so "the first pane's cwd" still matches herdr's own
/// branch derivation. No `pane.process_info` is needed (git status comes from
/// the cwd, not any shell PID).
///
/// Reading the two collections separately (`workspace.list` then one
/// `pane.list` per workspace) used to make this racy: a workspace closing
/// between the calls answered `workspace_not_found` and failed the whole
/// enumeration — which cost the daemon a strike toward the shutdown that clears
/// every status, and turned the dashboard into an error frame. A single call
/// cannot tear that way.
pub fn collect_spaces(client: &mut Herdr) -> crate::Result<Vec<Space>> {
    let snapshot = client.session_snapshot()?;
    Ok(spaces_from_snapshot(snapshot.workspaces, &snapshot.panes))
}

/// Regroup a snapshot's flat pane list under its workspaces, in order.
///
/// Panes are bucketed by `workspace_id` with their relative order preserved, so
/// each space sees exactly what a per-workspace `pane.list` would have returned.
/// A pane whose workspace is absent from `workspaces` is ignored.
fn spaces_from_snapshot(workspaces: Vec<WorkspaceInfo>, panes: &[PaneInfo]) -> Vec<Space> {
    let mut by_workspace: HashMap<&str, Vec<&PaneInfo>> = HashMap::new();
    for pane in panes {
        by_workspace
            .entry(pane.workspace_id.as_str())
            .or_default()
            .push(pane);
    }

    workspaces
        .into_iter()
        .map(|ws| {
            let panes = by_workspace
                .get(ws.workspace_id.as_str())
                .map(Vec::as_slice)
                .unwrap_or_default();
            space_from(ws, panes)
        })
        .collect()
}

/// Fold one workspace and its panes into a [`Space`]: classify the panes and
/// pick the cwd git will run in.
///
/// The cwd is the first pane's `cwd` — herdr's own record of that pane's shell
/// working directory, which it keeps up to date. herdr also reports a
/// `foreground_cwd`, which [`PaneInfo`] deliberately does not model: it is
/// sampled off the foreground process, and since 0.8.0 stopped letting those
/// checks block API handling (#1838, #2206) it can transiently read `/` or point
/// inside whatever binary is running. Running `git` there would report the wrong
/// repo, or none. Do not "modernise" this to `foreground_cwd`.
fn space_from(ws: WorkspaceInfo, panes: &[&PaneInfo]) -> Space {
    let mut agent_panes = Vec::new(); // panes with a real agent
    let mut spare_panes = Vec::new(); // plain shell panes — pseudo-agent hosts
    let mut pseudo_panes = Vec::new(); // panes already carrying our "git" agent
    let mut cwd: Option<String> = None;

    for pane in panes {
        // First pane with a non-empty cwd wins.
        if cwd.is_none() {
            if let Some(c) = pane.cwd.as_deref().filter(|c| !c.is_empty()) {
                cwd = Some(c.to_string());
            }
        }
        match pane.agent.as_deref() {
            Some(PSEUDO_AGENT) => pseudo_panes.push(pane.pane_id.clone()),
            Some(agent) if !agent.is_empty() => agent_panes.push(pane.pane_id.clone()),
            _ => spare_panes.push(pane.pane_id.clone()),
        }
    }

    let label = if ws.label.is_empty() {
        ws.workspace_id.clone()
    } else {
        ws.label.clone()
    };

    Space {
        id: ws.workspace_id,
        label,
        focused: ws.focused,
        pane_count: panes.len(),
        cwd,
        agent_panes,
        spare_panes,
        pseudo_panes,
        ..Default::default()
    }
}

/// Tag worktree-child spaces with their group parent, one `worktree.list` per
/// unique repo. Children whose repo's main checkout is open get `family_parent`.
///
/// `worktree.list` errors for non-repo workspaces; that error is folded into
/// "leave it standalone". Parent/child resolution is done against an id→index
/// map and applied after the query loop so we never hold a `&mut` into `spaces`
/// while borrowing `client`.
pub fn group_worktree_families(client: &mut Herdr, spaces: &mut [Space]) {
    let index_of: HashMap<String, usize> = spaces
        .iter()
        .enumerate()
        .map(|(i, s)| (s.id.clone(), i))
        .collect();
    let ids: Vec<String> = spaces.iter().map(|s| s.id.clone()).collect();

    let mut seen_repos: HashSet<String> = HashSet::new();
    let mut assignments: Vec<(usize, String)> = Vec::new(); // (child index, parent id)

    for ws_id in &ids {
        let res = match client.worktree_list(ws_id) {
            Ok(res) => res,
            Err(_) => continue, // workspace isn't in a git repo
        };
        let repo_key = res.source.repo_key;
        if repo_key.is_empty() || seen_repos.contains(&repo_key) {
            continue;
        }
        seen_repos.insert(repo_key);

        // The family only forms when the repo's main checkout is itself open.
        let parent_id = match res.source.source_workspace_id {
            Some(id) if index_of.contains_key(&id) => id,
            _ => continue, // main checkout isn't open — children stay standalone
        };
        for wt in res.worktrees {
            if let Some(child_id) = wt.open_workspace_id {
                if let Some(&child_idx) = index_of.get(&child_id) {
                    if child_id != parent_id {
                        assignments.push((child_idx, parent_id.clone()));
                    }
                }
            }
        }
    }

    for (child_idx, parent_id) in assignments {
        spaces[child_idx].family_parent = Some(parent_id);
    }
}

/// Full pipeline: collect → group worktrees → drop children → git status.
///
/// Worktree children are dropped (they render as single-row indented sidebar
/// entries — no status row), then `git status` is run once per surviving space.
pub fn snapshot(client: &mut Herdr) -> crate::Result<Vec<Space>> {
    let mut spaces = collect_spaces(client)?;
    group_worktree_families(client, &mut spaces);
    spaces.retain(|s| s.family_parent.is_none());
    for sp in &mut spaces {
        sp.git = git::status(sp.cwd.as_deref());
    }
    Ok(spaces)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn child_of(id: &str, parent: Option<&str>) -> Space {
        Space {
            id: id.to_string(),
            label: id.to_string(),
            family_parent: parent.map(str::to_string),
            ..Default::default()
        }
    }

    fn ws(id: &str, label: &str) -> WorkspaceInfo {
        WorkspaceInfo {
            workspace_id: id.to_string(),
            label: label.to_string(),
            focused: false,
        }
    }

    fn pane(id: &str, ws_id: &str, cwd: Option<&str>, agent: Option<&str>) -> PaneInfo {
        PaneInfo {
            pane_id: id.to_string(),
            workspace_id: ws_id.to_string(),
            cwd: cwd.map(str::to_string),
            agent: agent.map(str::to_string),
        }
    }

    /// `space_from` takes the borrowed slice `spaces_from_snapshot` builds.
    fn refs(panes: &[PaneInfo]) -> Vec<&PaneInfo> {
        panes.iter().collect()
    }

    // ---- space_from: pane classification + cwd choice ------------------------

    #[test]
    fn space_from_sorts_panes_into_agent_spare_and_pseudo() {
        let panes = [
            pane("p1", "w1", Some("/repo"), None),           // plain shell
            pane("p2", "w1", Some("/repo"), Some("claude")), // real agent
            pane("p3", "w1", Some("/repo"), Some(PSEUDO_AGENT)), // ours
            pane("p4", "w1", Some("/repo"), Some("")),       // empty agent == spare
        ];
        let sp = space_from(ws("w1", "repo"), &refs(&panes));
        assert_eq!(sp.spare_panes, ["p1", "p4"]);
        assert_eq!(sp.agent_panes, ["p2"]);
        assert_eq!(sp.pseudo_panes, ["p3"]);
        assert_eq!(sp.pane_count, 4);
    }

    #[test]
    fn space_from_takes_the_first_non_empty_cwd() {
        // A missing and an empty cwd are both skipped, so git runs in the first
        // pane that actually reports one.
        let panes = [
            pane("p1", "w1", None, None),
            pane("p2", "w1", Some(""), None),
            pane("p3", "w1", Some("/repo"), None),
            pane("p4", "w1", Some("/other"), None),
        ];
        assert_eq!(
            space_from(ws("w1", "repo"), &refs(&panes)).cwd.as_deref(),
            Some("/repo")
        );
    }

    #[test]
    fn space_from_without_any_cwd_has_none() {
        // Nothing to run git in — the caller surfaces no status for the space.
        let panes = [
            pane("p1", "w1", None, None),
            pane("p2", "w1", Some(""), None),
        ];
        assert_eq!(space_from(ws("w1", "repo"), &refs(&panes)).cwd, None);
        // A space with no panes at all is equally cwd-less.
        assert_eq!(space_from(ws("w1", "repo"), &[]).cwd, None);
    }

    #[test]
    fn space_from_falls_back_to_the_id_when_unlabelled() {
        assert_eq!(space_from(ws("w1", ""), &[]).label, "w1");
        assert_eq!(space_from(ws("w1", "named"), &[]).label, "named");
    }

    // ---- spaces_from_snapshot: regrouping the flat pane list -----------------

    #[test]
    fn snapshot_regroups_panes_under_their_workspace_in_order() {
        // Interleaved on purpose: grouping must be by workspace_id, and each
        // space must keep the relative order it had in the flat list — that is
        // what makes "the first pane's cwd wins" the same answer `pane.list`
        // would have given.
        let panes = [
            pane("w1:p1", "w1", Some("/one"), None),
            pane("w2:p1", "w2", Some("/two"), None),
            pane("w1:p2", "w1", Some("/one-later"), None),
            pane("w2:p2", "w2", Some("/two-later"), Some("claude")),
        ];
        let spaces = spaces_from_snapshot(vec![ws("w1", "one"), ws("w2", "two")], &panes);

        assert_eq!(spaces.len(), 2);
        assert_eq!(spaces[0].id, "w1");
        assert_eq!(spaces[0].spare_panes, ["w1:p1", "w1:p2"]);
        assert_eq!(spaces[0].cwd.as_deref(), Some("/one"));
        assert_eq!(spaces[1].id, "w2");
        assert_eq!(spaces[1].spare_panes, ["w2:p1"]);
        assert_eq!(spaces[1].agent_panes, ["w2:p2"]);
        assert_eq!(spaces[1].cwd.as_deref(), Some("/two"));
    }

    #[test]
    fn snapshot_keeps_a_workspace_that_has_no_panes() {
        // Still a space, just one we can't run git in — the caller then
        // surfaces nothing for it rather than dropping it from the report.
        let spaces = spaces_from_snapshot(vec![ws("w1", "empty")], &[]);
        assert_eq!(spaces.len(), 1);
        assert_eq!(spaces[0].pane_count, 0);
        assert_eq!(spaces[0].cwd, None);
    }

    #[test]
    fn snapshot_ignores_panes_whose_workspace_is_absent() {
        // Defensive: a pane tagged with a workspace the snapshot didn't list
        // has nowhere to go, and must not invent a space.
        let panes = [pane("wX:p1", "wX", Some("/gone"), None)];
        let spaces = spaces_from_snapshot(vec![ws("w1", "one")], &panes);
        assert_eq!(spaces.len(), 1);
        assert_eq!(spaces[0].id, "w1");
        assert_eq!(spaces[0].pane_count, 0);
    }

    #[test]
    fn snapshot_would_drop_tagged_worktree_children() {
        // Mirror the retain step snapshot() applies after grouping.
        let mut spaces = vec![
            child_of("parent", None),
            child_of("wt-child", Some("parent")),
            child_of("standalone", None),
        ];
        spaces.retain(|s| s.family_parent.is_none());
        let ids: Vec<&str> = spaces.iter().map(|s| s.id.as_str()).collect();
        assert_eq!(ids, ["parent", "standalone"]);
    }
}
