import json
import heapq
import streamlit as st
import networkx as nx
import matplotlib.pyplot as plt
from datetime import datetime, timezone

st.set_page_config(
    page_title="RouteGuard | Network Analyzer",
    layout="wide",
)

st.title("RouteGuard")
st.caption("Interactive Link-State Routing & SPF Analyzer")

# ==================================================
# 0. Deterministic shortest path
# ==================================================

def shortest_path_stable(graph, source, target, weight="weight"):
    """
    Dijkstra with a deterministic tie-break:
    among equal-cost paths, pick the one whose node sequence is
    lexicographically smallest. Returns (path_list, cost) or (None, None).
    """
    if source not in graph or target not in graph:
        return None, None
    if source == target:
        return [source], 0

    heap = [(0, (source,), source)]
    best_dist = {source: 0}
    visited = set()

    while heap:
        cost, path_t, node = heapq.heappop(heap)

        if node in visited:
            continue
        if cost > best_dist.get(node, float("inf")):
            continue

        visited.add(node)

        if node == target:
            return list(path_t), cost

        for neighbor in graph.neighbors(node):
            if neighbor in visited or neighbor in path_t:
                continue
            w = graph[node][neighbor].get(weight, 1)
            new_cost = cost + w
            prev_best = best_dist.get(neighbor, float("inf"))
            if new_cost <= prev_best:
                if new_cost < prev_best:
                    best_dist[neighbor] = new_cost
                heapq.heappush(
                    heap, (new_cost, path_t + (neighbor,), neighbor)
                )

    return None, None
def find_lfas(graph, u, failed_neighbor, destination):
        """
        Return a list of (next_hop, path_from_next_hop, cost_from_next_hop)
        for neighbors of u (excluding failed_neighbor) that can reach
        destination without transiting u.
        """
        G_fail = graph.copy()
        if G_fail.has_edge(u, failed_neighbor):
            G_fail.remove_edge(u, failed_neighbor)
        if u in G_fail:
            G_fail.remove_node(u)

        result = []
        for n in graph.neighbors(u):
            if n == failed_neighbor:
                continue
            if n not in G_fail or destination not in G_fail:
                continue
            path, cost = shortest_path_stable(
                G_fail, n, destination, weight="weight"
            )
            if path is not None:
                result.append((n, path, cost))
        return result
      
def build_analysis_report(G, source, destination, original_path, original_cost):
    """
    Build a JSON-serializable snapshot of the current analysis.
    Assumes original_path is not None and source != destination.
    """
    baseline = {
        "path": list(original_path),
        "cost": original_cost,
        "hops": len(original_path) - 1,
    }

    topology = {
        "routers": sorted(G.nodes()),
        "links": [
            {"from": u, "to": v, "cost": G[u][v]["weight"]}
            for u, v in sorted(G.edges())
        ],
    }

    # --- ECMP ---
    ecmp_raw = []
    for p in nx.all_simple_paths(G, source, destination):
        cost = sum(G[p[i]][p[i + 1]]["weight"] for i in range(len(p) - 1))
        if cost == original_cost:
            ecmp_raw.append(tuple(p))
    ecmp_paths = sorted(set(ecmp_raw))
    ecmp = {
        "count": len(ecmp_paths),
        "paths": [
            {"path": list(p), "cost": original_cost, "hops": len(p) - 1}
            for p in ecmp_paths
        ],
    }

    # --- Disjoint backup ---
    primary_edges = list(zip(original_path[:-1], original_path[1:]))
    G_disjoint = G.copy()
    for u, v in primary_edges:
        if G_disjoint.has_edge(u, v):
            G_disjoint.remove_edge(u, v)
    disjoint_path, disjoint_cost = shortest_path_stable(
        G_disjoint, source, destination, weight="weight"
    )
    disjoint = {
        "exists": disjoint_path is not None,
        "path": list(disjoint_path) if disjoint_path else None,
        "cost": disjoint_cost,
        "extra_cost": (
            (disjoint_cost - original_cost)
            if disjoint_cost is not None else None
        ),
    }

    # --- Failure impact ---
    impact = []
    for u, v in sorted(G.edges()):
        G_test = G.copy()
        G_test.remove_edge(u, v)
        new_path, new_cost = shortest_path_stable(
            G_test, source, destination, weight="weight"
        )
        if new_path is None:
            status = "disconnected"
            delta = None
            hops = None
            new_path_ser = None
        else:
            status = "no_change" if new_path == original_path else "rerouted"
            delta = new_cost - original_cost
            hops = len(new_path) - 1
            new_path_ser = list(new_path)
        impact.append({
            "failed_link": f"{u}-{v}",
            "link_cost": G[u][v]["weight"],
            "status": status,
            "new_cost": new_cost,
            "delta_cost": delta,
            "hops": hops,
            "new_path": new_path_ser,
        })

    # --- LFA coverage ---
    lfa_per_link = []
    covered = 0
    for u, v in primary_edges:
        lfas = find_lfas(G, u, v, destination)
        if lfas:
            covered += 1
            best = min(lfas, key=lambda x: (x[2], x[0]))
            n, path_from_n, cost_from_n = best
            repair_path = [u] + list(path_from_n)
            repair_cost = G[u][n]["weight"] + cost_from_n
            lfa_per_link.append({
                "protected_link": f"{u}-{v}",
                "upstream": u,
                "status": "protected",
                "num_lfas": len(lfas),
                "best_next_hop": n,
                "repair_path": repair_path,
                "repair_cost": repair_cost,
            })
        else:
            lfa_per_link.append({
                "protected_link": f"{u}-{v}",
                "upstream": u,
                "status": "no_lfa",
                "num_lfas": 0,
                "best_next_hop": None,
                "repair_path": None,
                "repair_cost": None,
            })

    total_links = len(primary_edges)
    lfa = {
        "total_links": total_links,
        "protected_links": covered,
        "coverage_pct": round(
            (covered / total_links * 100) if total_links else 0, 2
        ),
        "per_link": lfa_per_link,
    }

    return {
        "meta": {
            "tool": "RouteGuard",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "source": source,
            "destination": destination,
        },
        "topology": topology,
        "baseline_route": baseline,
        "ecmp": ecmp,
        "disjoint_backup": disjoint,
        "failure_impact": impact,
        "lfa_coverage": lfa,
    }

# ==================================================
# 1. Initialize editable topology
# ==================================================

INITIAL_EDGES = [
    ("R1", "R2", 2),
    ("R1", "R3", 4),
    ("R2", "R3", 1),
    ("R2", "R4", 5),
    ("R3", "R4", 2),
    ("R3", "R5", 6),
    ("R4", "R5", 1),
    ("R4", "R6", 4),
    ("R5", "R6", 2),
]

ROUTERS = ["R1", "R2", "R3", "R4", "R5", "R6"]

POSITIONS = {
    "R1": (0, 2),
    "R2": (1, 3),
    "R3": (1, 1),
    "R4": (2, 2),
    "R5": (3, 1),
    "R6": (4, 2),
}

if "links" not in st.session_state:
    st.session_state.links = {
        tuple(sorted((u, v))): cost for u, v, cost in INITIAL_EDGES
    }


def save_topology_callback():
    """Commit the simulated link failure into the baseline topology."""
    failed = st.session_state.get("failed_link_select", "None")
    if failed and failed != "None":
        u, v = failed.split("-")
        key = tuple(sorted((u, v)))
        st.session_state.links.pop(key, None)
    st.session_state["failed_link_select"] = "None"


def reset_topology_callback():
    """Restore the initial default topology used at startup."""
    st.session_state.links = {
        tuple(sorted((u, v))): cost for u, v, cost in INITIAL_EDGES
    }
    st.session_state["failed_link_select"] = "None"


# ==================================================
# 2. Sidebar — Topology editor
# ==================================================

st.sidebar.header("Topology Editor")

with st.sidebar.form("add_update_link"):
    st.subheader("Add or Update Link")
    router_a = st.selectbox("Router A", ROUTERS, index=0, key="router_a")
    router_b = st.selectbox("Router B", ROUTERS, index=1, key="router_b")
    cost = st.number_input(
        "Link Cost", min_value=1, max_value=1000, value=3, step=1
    )
    save_link = st.form_submit_button("Save Link")

    if save_link:
        if router_a == router_b:
            st.error("Choose two different routers.")
        else:
            key = tuple(sorted((router_a, router_b)))
            st.session_state.links[key] = int(cost)
            st.rerun()

current_links = sorted(st.session_state.links.keys())

if current_links:
    with st.sidebar.form("remove_link"):
        st.subheader("Remove Link")
        link_to_remove = st.selectbox(
            "Select Link",
            current_links,
            format_func=lambda edge: (
                f"{edge[0]} - {edge[1]} "
                f"(cost {st.session_state.links[edge]})"
            ),
        )
        remove_link = st.form_submit_button("Remove Selected Link")
        if remove_link:
            del st.session_state.links[link_to_remove]
            st.rerun()


# ==================================================
# 3. Build the current graph
# ==================================================

G = nx.Graph()
G.add_nodes_from(ROUTERS)

for (u, v), cost in st.session_state.links.items():
    G.add_edge(u, v, weight=cost)


# ==================================================
# 4. Sidebar — Routing controls
# ==================================================

st.sidebar.divider()
st.sidebar.header("Routing Controls")

source = st.sidebar.selectbox(
    "Source Router", ROUTERS, index=0, key="source_router"
)

destination = st.sidebar.selectbox(
    "Destination Router", ROUTERS, index=5, key="destination_router"
)

active_edges = sorted(G.edges())
failure_options = ["None"] + [f"{u}-{v}" for u, v in active_edges]

failed_link = st.sidebar.selectbox(
    "Simulate Link Failure",
    failure_options,
    key="failed_link_select",
)

st.sidebar.divider()

st.sidebar.button(
    "💾 Save Current Topology as Baseline",
    on_click=save_topology_callback,
    disabled=(failed_link == "None"),
    use_container_width=True,
    help=(
        "Permanently removes the simulated failed link and uses the "
        "current topology as the new baseline."
    ),
)

st.sidebar.button(
    "🔄 Reset Original Topology",
    on_click=reset_topology_callback,
    use_container_width=True,
    help="Restore the default topology used when the app started.",
)

H = G.copy()

if failed_link != "None":
    u, v = failed_link.split("-")
    H.remove_edge(u, v)


# ==================================================
# 5. Compute routes (baseline and post-failure)
# ==================================================

def calculate_route(graph, start, end):
    return shortest_path_stable(graph, start, end, weight="weight")


original_path, original_cost = calculate_route(G, source, destination)
path, path_cost = calculate_route(H, source, destination)

path_edges = set()
if path:
    for u, v in zip(path[:-1], path[1:]):
        path_edges.add(frozenset((u, v)))

failed_edge = (
    frozenset(failed_link.split("-"))
    if failed_link != "None"
    else None
)

green_edges = []
gray_edges = []
red_edges = []

for u, v in G.edges():
    edge_key = frozenset((u, v))
    if edge_key == failed_edge:
        red_edges.append((u, v))
    elif H.has_edge(u, v) and edge_key in path_edges:
        green_edges.append((u, v))
    else:
        gray_edges.append((u, v))


# ==================================================
# MAIN VIEW — Route analysis + topology diagram
# ==================================================

st.subheader(f"Route Analysis: {source} → {destination}")

if original_path is not None:
    col1, col2 = st.columns(2)

    with col1:
        st.markdown("### Before Failure")
        st.metric("Route Cost", original_cost)
        st.write(" → ".join(original_path))
        st.caption(f"{len(original_path) - 1} hops")

    with col2:
        st.markdown("### After Failure")
        if path is not None:
            st.metric(
                "Route Cost",
                path_cost,
                delta=path_cost - original_cost,
                delta_color="inverse",
            )
            st.write(" → ".join(path))
            st.caption(f"{len(path) - 1} hops")
        else:
            st.error("Destination is unreachable after failure.")

    if path is None:
        st.warning(
            "The selected link failure disconnects the destination "
            "from the source."
        )
    elif path == original_path:
        st.info(
            "The selected failure did not change the chosen shortest path."
        )
    else:
        st.success(
            "The route changed after failure. "
            "The new route has been highlighted in the topology."
        )
else:
    st.error("No original route exists between the selected routers.")


# ---- Topology diagram (always visible at top) ------------------------

fig, ax = plt.subplots(figsize=(11, 5))

nx.draw_networkx_nodes(
    G, POSITIONS, node_size=1400,
    node_color=[
        "#B7E4C7" if n == source
        else "#FFD6A5" if n == destination
        else "#DCE6F1"
        for n in G.nodes()
    ],
    ax=ax,
)

nx.draw_networkx_labels(G, POSITIONS, font_size=11, ax=ax)

nx.draw_networkx_edges(
    G, POSITIONS, edgelist=gray_edges,
    edge_color="#A0A0A0", width=1.5, ax=ax,
)

nx.draw_networkx_edges(
    G, POSITIONS, edgelist=green_edges,
    edge_color="green", width=4, ax=ax,
)

nx.draw_networkx_edges(
    G, POSITIONS, edgelist=red_edges,
    edge_color="red", style="dashed", width=3, ax=ax,
)

nx.draw_networkx_edge_labels(
    G, POSITIONS,
    edge_labels=nx.get_edge_attributes(G, "weight"),
    font_size=10, ax=ax,
)

ax.set_axis_off()
st.pyplot(fig)
plt.close(fig)

st.caption(
    "Green: selected shortest path | "
    "Gray: other links | "
    "Red dashed: simulated failed link"
)


# ==================================================
# ANALYSIS TABS
# ==================================================

(
    tab_route, tab_backup, tab_impact, tab_disjoint,
    tab_ecmp, tab_lfa, tab_spf, tab_export,
) = st.tabs([
    "📍 Route Details",
    "🔁 Backup (per-link)",
    "💥 Failure Impact",
    "🛡️ Disjoint Backup",
    "⚖️ ECMP",
    "🚑 LFA Coverage",
    "🧮 SPF Trace",
    "📤 Export",
])


# --------------------------------------------------
# Tab 1 — Selected Route Details
# --------------------------------------------------

with tab_route:
    st.subheader("Selected Route Details")

    if path is not None:
        route_rows = []
        for u, v in zip(path[:-1], path[1:]):
            route_rows.append({
                "From": u,
                "To": v,
                "Link Cost": H[u][v]["weight"],
            })

        if route_rows:
            st.dataframe(
                route_rows, use_container_width=True, hide_index=True
            )
        else:
            st.info("Source and destination are the same router.")
    else:
        st.warning("No post-failure path available for this pair.")


# --------------------------------------------------
# Tab 2 — Backup Path Analysis (per-link repair)
# --------------------------------------------------

with tab_backup:
    st.subheader("Backup Path Analysis")
    st.caption(
        "Removes one selected primary-path link and computes the shortest "
        "path in what remains. This is the per-link repair view — see the "
        "'Disjoint Backup' tab for a path-diversity view."
    )

    backup_path = None
    backup_cost = None
    protected_link = None

    if source == destination:
        st.info("Source and destination are the same router.")
    elif original_path is None or len(original_path) < 2:
        st.error("No primary path exists, so backup analysis cannot run.")
    else:
        primary_links = [
            (original_path[i], original_path[i + 1])
            for i in range(len(original_path) - 1)
        ]

        protected_link = st.selectbox(
            "Assume this primary-path link fails:",
            [f"{u}-{v}" for u, v in primary_links],
            index=0,
            key="protected_link_select",
            help=(
                "Backup computed on the topology with this link removed, "
                "the way an FRR / LFA repair would be calculated."
            ),
        )

        u, v = protected_link.split("-")

        G_backup = G.copy()
        if G_backup.has_edge(u, v):
            G_backup.remove_edge(u, v)

        backup_path, backup_cost = shortest_path_stable(
            G_backup, source, destination, weight="weight"
        )

    if (
        source != destination
        and original_path is not None
        and protected_link is not None
    ):
        if backup_path is None:
            st.error(
                f"No backup path exists when **{protected_link}** fails. "
                "The destination becomes unreachable — this link has no "
                "local repair."
            )
        else:
            col1, col2, col3 = st.columns(3)
            col1.metric("Primary Path Cost", original_cost)
            col2.metric("Backup Path Cost", backup_cost)
            col3.metric(
                "Extra Cost",
                backup_cost - original_cost,
                delta_color="inverse",
            )

            st.write("**Primary Path:**", " → ".join(original_path))
            st.write("**Backup Path:**", " → ".join(backup_path))
            st.caption(
                f"Backup computed on the topology with **{protected_link}** "
                "removed (default: first hop of the primary path)."
            )

            primary_set = {
                frozenset(e) for e in zip(original_path[:-1], original_path[1:])
            }
            backup_set = {
                frozenset(e) for e in zip(backup_path[:-1], backup_path[1:])
            }
            shared = primary_set & backup_set

            if not shared:
                st.success(
                    "Backup path is fully link-disjoint from the primary "
                    "path."
                )
            else:
                shared_str = ", ".join(
                    f"{a}-{b}" for a, b in (tuple(s) for s in shared)
                )
                st.warning(
                    f"Backup shares the following link(s) with the primary: "
                    f"{shared_str}. It only protects against failure of "
                    f"**{protected_link}**."
                )


# --------------------------------------------------
# Tab 3 — Failure Impact Analyzer
# --------------------------------------------------

with tab_impact:
    st.subheader("Failure Impact Analyzer")
    st.caption(
        "Every link in the baseline topology is failed one at a time. "
        "For the current source → destination pair we report whether "
        "the destination stays reachable, whether the shortest path "
        "changes, and how much the cost increases. Independent of the "
        "'Simulate Link Failure' selection."
    )

    if source == destination:
        st.info("Pick two different routers to run failure analysis.")
    elif original_path is None:
        st.error("No baseline path exists, so failure analysis cannot run.")
    else:
        impact_rows = []

        for u, v in sorted(G.edges()):
            G_test = G.copy()
            G_test.remove_edge(u, v)

            new_path, new_cost = shortest_path_stable(
                G_test, source, destination, weight="weight"
            )

            if new_path is None:
                status = "🔴 Disconnected"
                cost_delta = None
                hops = None
                path_str = "—"
            else:
                hops = len(new_path) - 1
                cost_delta = new_cost - original_cost
                path_str = " → ".join(new_path)
                if new_path == original_path:
                    status = "🟢 No change"
                else:
                    status = "🟡 Rerouted"

            impact_rows.append({
                "Failed Link": f"{u}-{v}",
                "Link Cost": G[u][v]["weight"],
                "Status": status,
                "New Cost": new_cost,
                "Δ Cost": cost_delta,
                "Hops": hops,
                "New Path": path_str,
            })

        total = len(impact_rows)
        disconnected = sum(
            1 for r in impact_rows if r["Status"] == "🔴 Disconnected"
        )
        unchanged = sum(
            1 for r in impact_rows if r["Status"] == "🟢 No change"
        )
        rerouted = sum(
            1 for r in impact_rows if r["Status"] == "🟡 Rerouted"
        )

        m1, m2, m3, m4 = st.columns(4)
        m1.metric("Links Tested", total)
        m2.metric("Disconnects", disconnected)
        m3.metric("Reroutes", rerouted)
        m4.metric("No Change", unchanged)

        st.dataframe(
            impact_rows, use_container_width=True, hide_index=True
        )

        if disconnected:
            critical = [
                r["Failed Link"] for r in impact_rows
                if r["Status"] == "🔴 Disconnected"
            ]
            st.warning(
                f"**{disconnected} critical link(s)** disconnect "
                f"{destination} from {source}: {', '.join(critical)}"
            )
        else:
            st.success(
                f"The topology is **1-link resilient** between {source} "
                f"and {destination}: no single link failure disconnects them."
            )


# --------------------------------------------------
# Tab 4 — Link-Disjoint Backup Path
# --------------------------------------------------

with tab_disjoint:
    st.subheader("Link-Disjoint Backup Path")
    st.caption(
        "Finds a backup that shares **zero** links with the primary path "
        "— true path diversity. Computed on the baseline topology."
    )

    if source == destination:
        st.info("Pick two different routers.")
    elif original_path is None or len(original_path) < 2:
        st.error("No primary path exists.")
    else:
        primary_edges = list(zip(original_path[:-1], original_path[1:]))

        G_disjoint = G.copy()
        for u, v in primary_edges:
            if G_disjoint.has_edge(u, v):
                G_disjoint.remove_edge(u, v)

        disjoint_path, disjoint_cost = shortest_path_stable(
            G_disjoint, source, destination, weight="weight"
        )

        if disjoint_path is None:
            st.warning(
                f"No link-disjoint backup exists between **{source}** and "
                f"**{destination}**. Every alternate path shares at least "
                "one link with the primary."
            )
        else:
            col1, col2, col3 = st.columns(3)
            col1.metric("Primary Cost", original_cost)
            col2.metric("Disjoint Backup Cost", disjoint_cost)
            col3.metric(
                "Extra Cost",
                disjoint_cost - original_cost,
                delta_color="inverse",
            )

            st.write("**Primary Path:**", " → ".join(original_path))
            st.write("**Disjoint Backup:**", " → ".join(disjoint_path))

            st.success(
                "Backup shares **zero** links with the primary. It "
                "survives failure of any single primary-path link."
            )

            with st.expander("Visualize primary vs link-disjoint backup"):
                primary_set = {frozenset(e) for e in primary_edges}
                disjoint_set = {
                    frozenset(e)
                    for e in zip(disjoint_path[:-1], disjoint_path[1:])
                }

                fig3, ax3 = plt.subplots(figsize=(11, 5))

                nx.draw_networkx_nodes(
                    G, POSITIONS, node_size=1400,
                    node_color=[
                        "#B7E4C7" if n == source
                        else "#FFD6A5" if n == destination
                        else "#DCE6F1"
                        for n in G.nodes()
                    ],
                    ax=ax3,
                )
                nx.draw_networkx_labels(G, POSITIONS, font_size=11, ax=ax3)

                other = [
                    e for e in G.edges()
                    if frozenset(e) not in primary_set | disjoint_set
                ]
                primary_edges_draw = [
                    e for e in G.edges() if frozenset(e) in primary_set
                ]
                disjoint_edges_draw = [
                    e for e in G.edges() if frozenset(e) in disjoint_set
                ]

                nx.draw_networkx_edges(
                    G, POSITIONS, edgelist=other,
                    edge_color="#C8C8C8", width=1.5, ax=ax3,
                )
                nx.draw_networkx_edges(
                    G, POSITIONS, edgelist=primary_edges_draw,
                    edge_color="green", width=4, ax=ax3,
                )
                nx.draw_networkx_edges(
                    G, POSITIONS, edgelist=disjoint_edges_draw,
                    edge_color="orange", width=4, style="dashed", ax=ax3,
                )
                nx.draw_networkx_edge_labels(
                    G, POSITIONS,
                    edge_labels=nx.get_edge_attributes(G, "weight"),
                    font_size=10, ax=ax3,
                )
                ax3.set_axis_off()
                st.pyplot(fig3)
                plt.close(fig3)


# --------------------------------------------------
# Tab 5 — Equal-Cost Multipath (ECMP)
# --------------------------------------------------

with tab_ecmp:
    st.subheader("Equal-Cost Multipath (ECMP)")
    st.caption(
        "All shortest paths between source and destination on the "
        "baseline topology. When more than one exists, a link-state "
        "router installs all of them and load-balances across them."
    )

    if source == destination:
        st.info("Pick two different routers.")
    elif original_path is None:
        st.error("No baseline path exists, so ECMP cannot be evaluated.")
    else:
        candidates = []
        for p in nx.all_simple_paths(G, source, destination):
            cost = sum(
                G[p[i]][p[i + 1]]["weight"] for i in range(len(p) - 1)
            )
            if cost == original_cost:
                candidates.append((tuple(p), cost))

        ecmp_paths = sorted({p for p, _ in candidates})

        st.metric("Equal-cost paths found", len(ecmp_paths))
        st.write("**Shortest path cost:**", original_cost)

        if len(ecmp_paths) == 1:
            st.info(
                "Only one shortest path exists between these routers — "
                "no ECMP at this destination."
            )
        else:
            st.success(
                f"{len(ecmp_paths)} equal-cost paths. A router would "
                "load-balance across all of them."
            )

        ecmp_rows = [
            {
                "Path": " → ".join(p),
                "Hops": len(p) - 1,
                "Cost": original_cost,
            }
            for p in ecmp_paths
        ]
        st.dataframe(ecmp_rows, use_container_width=True, hide_index=True)

        if len(ecmp_paths) > 1:
            edge_sets = [
                {frozenset(e) for e in zip(p[:-1], p[1:])}
                for p in ecmp_paths
            ]
            common = set.intersection(*edge_sets)
            if common:
                common_str = ", ".join(
                    f"{a}-{b}" for a, b in (tuple(s) for s in common)
                )
                st.caption(
                    f"Links common to every ECMP path: **{common_str}**. "
                    "These are single points of failure even under "
                    "load-balancing."
                )
            else:
                st.caption(
                    "No link is common to all ECMP paths — the destination "
                    "survives any single-link failure under ECMP."
                )


# --------------------------------------------------
# Tab 6 — LFA / Link-Protection Coverage
# --------------------------------------------------

with tab_lfa:
    st.subheader("LFA / Link-Protection Coverage")
    st.caption(
        "For each primary-path link (u, v), this checks whether the "
        "upstream router u has an alternate neighbor that can reach the "
        "destination without transiting u. That is the local-repair "
        "condition used by LFA / FRR. Computed on the baseline topology, "
        "per router."
    )


    if source == destination:
        st.info("Pick two different routers.")
    elif original_path is None or len(original_path) < 2:
        st.error("No primary path exists.")
    else:
        primary_edges = list(zip(original_path[:-1], original_path[1:]))

        lfa_rows = []
        covered = 0

        for u, v in primary_edges:
            lfas = find_lfas(G, u, v, destination)

            if not lfas:
                status = "🔴 No LFA"
                best = None
            else:
                covered += 1
                status = "🟢 Protected"
                best = min(lfas, key=lambda x: (x[2], x[0]))

            repair_path = None
            repair_cost_from_u = None
            if best:
                n, path_from_n, cost_from_n = best
                repair_path = [u] + list(path_from_n)
                repair_cost_from_u = G[u][n]["weight"] + cost_from_n

            lfa_rows.append({
                "Protected Link": f"{u}-{v}",
                "Upstream": u,
                "Status": status,
                "# LFAs": len(lfas),
                "LFA Next-Hop": best[0] if best else "—",
                "Repair Path (from u)": (
                    " → ".join(repair_path) if repair_path else "—"
                ),
                "Repair Cost (from u)": repair_cost_from_u,
            })

        total = len(primary_edges)
        coverage_pct = (covered / total * 100) if total else 0

        m1, m2, m3 = st.columns(3)
        m1.metric("Primary-path links", total)
        m2.metric("Protected by LFA", covered)
        m3.metric("Coverage", f"{coverage_pct:.0f}%")

        st.dataframe(lfa_rows, use_container_width=True, hide_index=True)

        if covered == total:
            st.success(
                "Full LFA coverage: every primary-path link has a local "
                "repair. FRR can protect the entire path without waiting "
                "for IGP reconvergence."
            )
        elif covered == 0:
            st.error(
                "No LFA coverage: no primary-path link has a local repair. "
                "Every failure would require full IGP reconvergence."
            )
        else:
            uncovered = [
                r["Protected Link"] for r in lfa_rows
                if r["Status"] == "🔴 No LFA"
            ]
            st.warning(
                f"Partial coverage: {total - covered} of {total} "
                f"primary-path link(s) have no LFA and would require full "
                f"reconvergence — {', '.join(uncovered)}."
            )

        st.caption(
            "Repair paths are local to each upstream router — they are "
            "what the router would install in its FIB *before* any "
            "failure. This is why the numbers here can differ from the "
            "'Backup (per-link)' tab, which recomputes a shortest path "
            "from the source after removing the link."
        )


# --------------------------------------------------
# Tab 7 — IS-IS-style SPF Computation
# --------------------------------------------------

with tab_spf:
    st.subheader("IS-IS-style SPF Computation")
    st.caption(
        "Dijkstra's algorithm traced from the source router using the "
        "same vocabulary a link-state IGP (IS-IS, OSPF) uses: tentative "
        "distance, candidate list, predecessor, finalization."
    )

    def spf_trace(graph, root, weight="weight"):
        tent = {root: 0}
        pred = {root: None}
        visited = set()
        steps = []
        candidates = [(0, root)]

        while candidates:
            candidates.sort()
            cost, node = candidates.pop(0)

            if node in visited:
                continue
            visited.add(node)

            relaxations = []

            for nb in sorted(graph.neighbors(node)):
                if nb in visited:
                    continue
                w = graph[node][nb].get(weight, 1)
                new_cost = cost + w
                old = tent.get(nb, float("inf"))

                if new_cost < old:
                    tent[nb] = new_cost
                    pred[nb] = node
                    candidates.append((new_cost, nb))
                    relaxations.append({
                        "neighbor": nb,
                        "edge_cost": w,
                        "old_td": old,
                        "new_td": new_cost,
                        "action": "NEW" if old == float("inf") else "UPDATE",
                    })
                elif new_cost == old:
                    if pred.get(nb) is None or node < pred[nb]:
                        pred[nb] = node
                    relaxations.append({
                        "neighbor": nb,
                        "edge_cost": w,
                        "old_td": old,
                        "new_td": new_cost,
                        "action": "TIE (kept smaller pred)",
                    })
                else:
                    relaxations.append({
                        "neighbor": nb,
                        "edge_cost": w,
                        "old_td": old,
                        "new_td": new_cost,
                        "action": "NO CHANGE",
                    })

            chain = []
            c = node
            while c is not None:
                chain.append(c)
                c = pred.get(c)
            chain.reverse()

            steps.append({
                "step": len(steps) + 1,
                "finalized": node,
                "cost": cost,
                "path": chain,
                "relaxations": relaxations,
            })

        return steps, tent, pred

    if source == destination:
        st.info("Pick two different routers.")
    else:
        steps, final_dist, final_pred = spf_trace(G, source)

        st.markdown(
            f"**Finalization order** — shortest distances from "
            f"**{source}** are confirmed in this order:"
        )
        summary_rows = [
            {
                "Step": s["step"],
                "Finalized": s["finalized"],
                "Cost": s["cost"],
                "Path from source": " → ".join(s["path"]),
            }
            for s in steps
        ]
        st.dataframe(
            summary_rows, use_container_width=True, hide_index=True
        )

        with st.expander("Full relaxation trace (step by step)"):
            for s in steps:
                st.markdown(
                    f"**Step {s['step']}** — finalize **{s['finalized']}** "
                    f"(cost `{s['cost']}`, path `{' → '.join(s['path'])}`)"
                )
                if not s["relaxations"]:
                    st.caption("No unvisited neighbors to relax.")
                else:
                    rel_rows = []
                    for r in s["relaxations"]:
                        old_str = (
                            "∞" if r["old_td"] == float("inf")
                            else str(r["old_td"])
                        )
                        new_str = (
                            old_str if r["action"] == "NO CHANGE"
                            else str(r["new_td"])
                        )
                        rel_rows.append({
                            "Neighbor": r["neighbor"],
                            "Edge Cost": r["edge_cost"],
                            "Old TD": old_str,
                            "New TD": new_str,
                            "Action": r["action"],
                        })
                    st.dataframe(
                        rel_rows, use_container_width=True, hide_index=True
                    )
                st.divider()

        st.markdown(
            f"**Routing table computed by {source}** "
            "(shortest-path tree — next hop for every destination):"
        )

        rt_rows = []
        for node in sorted(G.nodes()):
            if node == source:
                continue
            if node not in final_dist:
                rt_rows.append({
                    "Destination": node,
                    "Cost": "unreachable",
                    "Next-Hop": "—",
                    "Full Path": "—",
                })
                continue

            chain = []
            c = node
            while c is not None:
                chain.append(c)
                c = final_pred.get(c)
            chain.reverse()
            next_hop = chain[1] if len(chain) > 1 else "—"

            rt_rows.append({
                "Destination": node,
                "Cost": final_dist[node],
                "Next-Hop": next_hop,
                "Full Path": " → ".join(chain),
            })

        st.dataframe(rt_rows, use_container_width=True, hide_index=True)

        st.caption(
            "The SPF run here uses the same tie-break as "
            "`shortest_path_stable`, so the path chosen for the current "
            "target matches the other tabs exactly."
        )
# --------------------------------------------------
# Tab 8 — Export Analysis (JSON)
# --------------------------------------------------

with tab_export:
    st.subheader("Export Analysis (JSON)")
    st.caption(
        "A single JSON snapshot of everything the tool computed for the "
        "current source → destination pair: topology, baseline route, "
        "ECMP, disjoint backup, per-link failure impact, and LFA coverage. "
        "Useful for reproducing experiments, diffing topologies, or "
        "attaching to a report."
    )

    if source == destination:
        st.info("Pick two different routers.")
    elif original_path is None:
        st.error("No baseline path exists, so there is nothing to export.")
    else:
        report = build_analysis_report(
            G, source, destination, original_path, original_cost
        )
        json_str = json.dumps(report, indent=2, default=str)

        st.download_button(
            label="📥 Download report.json",
            data=json_str,
            file_name=f"routeguard_{source}_to_{destination}.json",
            mime="application/json",
        )

        with st.expander("Preview JSON", expanded=False):
            st.json(report)
            
            
            
# import heapq
# import streamlit as st
# import networkx as nx
# import matplotlib.pyplot as plt

# st.set_page_config(
#     page_title="RouteGuard | Network Analyzer",
#     layout="wide",
# )

# st.title("RouteGuard")
# st.caption("Interactive Link-State Routing & SPF Analyzer")

# # ----------------------------------
# # 0. Deterministic shortest path
# # ----------------------------------

# def shortest_path_stable(graph, source, target, weight="weight"):
#     """
#     Dijkstra with a deterministic tie-break:
#     among equal-cost paths, pick the one whose node sequence is
#     lexicographically smallest. Returns (path_list, cost) or (None, None).
#     """
#     if source not in graph or target not in graph:
#         return None, None
#     if source == target:
#         return [source], 0

#     # Heap entries: (cost, path_tuple, node).
#     # path_tuple is the tiebreaker -> lexicographically smallest wins.
#     heap = [(0, (source,), source)]
#     best_dist = {source: 0}
#     visited = set()

#     while heap:
#         cost, path_t, node = heapq.heappop(heap)

#         if node in visited:
#             continue
#         if cost > best_dist.get(node, float("inf")):
#             continue

#         visited.add(node)

#         if node == target:
#             return list(path_t), cost

#         for neighbor in graph.neighbors(node):
#             if neighbor in visited or neighbor in path_t:
#                 continue  # no revisits, no cycles
#             w = graph[node][neighbor].get(weight, 1)
#             new_cost = cost + w
#             prev_best = best_dist.get(neighbor, float("inf"))
#             if new_cost <= prev_best:
#                 if new_cost < prev_best:
#                     best_dist[neighbor] = new_cost
#                 heapq.heappush(
#                     heap, (new_cost, path_t + (neighbor,), neighbor)
#                 )

#     return None, None
  
# # ----------------------------------
# # 1. Initialize editable topology
# # ----------------------------------

# INITIAL_EDGES = [
#     ("R1", "R2", 2),
#     ("R1", "R3", 4),
#     ("R2", "R3", 1),
#     ("R2", "R4", 5),
#     ("R3", "R4", 2),
#     ("R3", "R5", 6),
#     ("R4", "R5", 1),
#     ("R4", "R6", 4),
#     ("R5", "R6", 2),
# ]

# ROUTERS = ["R1", "R2", "R3", "R4", "R5", "R6"]

# POSITIONS = {
#     "R1": (0, 2),
#     "R2": (1, 3),
#     "R3": (1, 1),
#     "R4": (2, 2),
#     "R5": (3, 1),
#     "R6": (4, 2),
# }

# if "links" not in st.session_state:
#     st.session_state.links = {
#         tuple(sorted((u, v))): cost for u, v, cost in INITIAL_EDGES
#     }
    

# # --- Save / Reset callbacks -------------------------------------------
# def save_topology_callback():
#     """Commit the simulated link failure into the baseline topology."""
#     failed = st.session_state.get("failed_link_select", "None")
#     if failed and failed != "None":
#         u, v = failed.split("-")
#         key = tuple(sorted((u, v)))
#         st.session_state.links.pop(key, None)
#     # Clear the failure selection so the baseline is clean
#     st.session_state["failed_link_select"] = "None"


# def reset_topology_callback():
#     """Restore the initial default topology used at startup."""
#     st.session_state.links = {
#         tuple(sorted((u, v))): cost for u, v, cost in INITIAL_EDGES
#     }
#     st.session_state["failed_link_select"] = "None"

# # ----------------------------------
# # 2. Topology editor
# # ----------------------------------

# st.sidebar.header("Topology Editor")

# with st.sidebar.form("add_update_link"):
#     st.subheader("Add or Update Link")
#     router_a = st.selectbox("Router A", ROUTERS, index=0, key="router_a")
#     router_b = st.selectbox("Router B", ROUTERS, index=1, key="router_b")
#     cost = st.number_input(
#         "Link Cost", min_value=1, max_value=1000, value=3, step=1
#     )
#     save_link = st.form_submit_button("Save Link")

#     if save_link:
#         if router_a == router_b:
#             st.error("Choose two different routers.")
#         else:
#             key = tuple(sorted((router_a, router_b)))
#             st.session_state.links[key] = int(cost)
#             st.rerun()

# current_links = sorted(st.session_state.links.keys())

# if current_links:
#     with st.sidebar.form("remove_link"):
#         st.subheader("Remove Link")
#         link_to_remove = st.selectbox(
#             "Select Link",
#             current_links,
#             format_func=lambda edge: (
#                 f"{edge[0]} - {edge[1]} "
#                 f"(cost {st.session_state.links[edge]})"
#             ),
#         )
#         remove_link = st.form_submit_button("Remove Selected Link")
#         if remove_link:
#             del st.session_state.links[link_to_remove]
#             st.rerun()


# # ----------------------------------
# # 3. Build the current graph
# # ----------------------------------

# G = nx.Graph()
# G.add_nodes_from(ROUTERS)

# for (u, v), cost in st.session_state.links.items():
#     G.add_edge(u, v, weight=cost)

# # ----------------------------------
# # 4. Routing controls
# # ----------------------------------

# st.sidebar.divider()
# st.sidebar.header("Routing Controls")

# source = st.sidebar.selectbox(
#     "Source Router",
#     ROUTERS,
#     index=0,
#     key="source_router"
# )

# destination = st.sidebar.selectbox(
#     "Destination Router",
#     ROUTERS,
#     index=5,
#     key="destination_router"
# )

# active_edges = sorted(G.edges())

# failure_options = ["None"] + [
#     f"{u}-{v}" for u, v in active_edges
# ]

# failed_link = st.sidebar.selectbox(
#     "Simulate Link Failure",
#     failure_options,
#     key="failed_link_select"
# )

# st.sidebar.divider()

# st.sidebar.button(
#     "💾 Save Current Topology as Baseline",
#     on_click=save_topology_callback,
#     disabled=(failed_link == "None"),
#     use_container_width=True,
#     help=(
#         "Permanently removes the simulated failed link and uses the "
#         "current topology as the new baseline. Backup path analysis "
#         "will be recalculated from this new baseline."
#     ),
# )

# st.sidebar.button(
#     "🔄 Reset Original Topology",
#     on_click=reset_topology_callback,
#     use_container_width=True,
#     help="Restore the default topology used when the app started.",
# )

# H = G.copy()

# if failed_link != "None":
#     u, v = failed_link.split("-")
#     H.remove_edge(u, v)


# # ----------------------------------
# # 5. Calculate original and new routes
# # ----------------------------------

# def calculate_route(graph, start, end):
#     return shortest_path_stable(graph, start, end, weight="weight")


# # Route before failure
# original_path, original_cost = calculate_route(
#     G, source, destination
# )

# # Route after the selected failure
# path, path_cost = calculate_route(
#     H, source, destination
# )

# # Use the post-failure route for visualization
# path_edges = set()

# if path:
#     for u, v in zip(path[:-1], path[1:]):
#         path_edges.add(frozenset((u, v)))


# # Classify links for visualization
# failed_edge = (
#     frozenset(failed_link.split("-"))
#     if failed_link != "None"
#     else None
# )

# green_edges = []
# gray_edges = []
# red_edges = []

# for u, v in G.edges():
#     edge_key = frozenset((u, v))

#     if edge_key == failed_edge:
#         red_edges.append((u, v))
#     elif H.has_edge(u, v) and edge_key in path_edges:
#         green_edges.append((u, v))
#     else:
#         gray_edges.append((u, v))


# # ----------------------------------
# # 6. Display route comparison
# # ----------------------------------

# st.subheader(f"Route Analysis: {source} → {destination}")

# if original_path is not None:
#     col1, col2 = st.columns(2)

#     with col1:
#         st.markdown("### Before Failure")
#         st.metric("Route Cost", original_cost)
#         st.write(" → ".join(original_path))
#         st.caption(f"{len(original_path) - 1} hops")

#     with col2:
#         st.markdown("### After Failure")
#         if path is not None:
#             st.metric(
#                 "Route Cost",
#                 path_cost,
#                 delta=path_cost - original_cost,
#                 delta_color="inverse"
#             )
#             st.write(" → ".join(path))
#             st.caption(f"{len(path) - 1} hops")
#         else:
#             st.error("Destination is unreachable after failure.")

#     if path is None:
#         st.warning(
#             "The selected link failure disconnects the destination "
#             "from the source."
#         )
#     elif path == original_path:
#         st.info(
#             "The selected failure did not change the chosen shortest path."
#         )
#     else:
#         st.success(
#             "The route changed after failure. "
#             "The new route has been highlighted in the topology."
#         )
# else:
#     st.error(
#         "No original route exists between the selected routers."
#     )

# st.divider()


# # ----------------------------------
# # 7. Visualize selected route only
# # ----------------------------------

# fig, ax = plt.subplots(figsize=(11, 5))

# nx.draw_networkx_nodes(
#     G,
#     POSITIONS,
#     node_size=1400,
#     node_color=[
#         "#B7E4C7" if n == source
#         else "#FFD6A5" if n == destination
#         else "#DCE6F1"
#         for n in G.nodes()
#     ],
#     ax=ax
# )

# nx.draw_networkx_labels(
#     G, POSITIONS, font_size=11, ax=ax
# )

# # All configured links that aren't on the route.
# nx.draw_networkx_edges(
#     G,
#     POSITIONS,
#     edgelist=gray_edges,
#     edge_color="#A0A0A0",
#     width=1.5,
#     ax=ax
# )

# # Only the selected source-to-destination path.
# nx.draw_networkx_edges(
#     G,
#     POSITIONS,
#     edgelist=green_edges,
#     edge_color="green",
#     width=4,
#     ax=ax
# )

# # Failed link shown separately.
# nx.draw_networkx_edges(
#     G,
#     POSITIONS,
#     edgelist=red_edges,
#     edge_color="red",
#     style="dashed",
#     width=3,
#     ax=ax
# )

# edge_labels = nx.get_edge_attributes(G, "weight")

# nx.draw_networkx_edge_labels(
#     G,
#     POSITIONS,
#     edge_labels=edge_labels,
#     font_size=10,
#     ax=ax
# )

# ax.set_axis_off()
# st.pyplot(fig)
# plt.close(fig)

# st.caption(
#     "Green: selected shortest path | "
#     "Gray: other links | "
#     "Red dashed: simulated failed link"
# )

# # ----------------------------------
# # 8. Selected route details
# # ----------------------------------

# st.subheader("Selected Route Details")

# if path is not None:
#     route_rows = []

#     for u, v in zip(path[:-1], path[1:]):
#         route_rows.append({
#             "From": u,
#             "To": v,
#             "Link Cost": H[u][v]["weight"]
#         })

#     if route_rows:
#         st.dataframe(
#             route_rows,
#             use_container_width=True,
#             hide_index=True
#         )
#     else:
#         st.info("Source and destination are the same router.")


# # --------------------------------------------------
# # 9. Backup Path Analysis
# # --------------------------------------------------

# st.header("9. Backup Path Analysis")

# backup_path = None
# backup_cost = None
# protected_link = None
# G_backup = None

# if source == destination:
#     st.info("Source and destination are the same router.")
# elif original_path is None or len(original_path) < 2:
#     st.error("No primary path exists, so backup analysis cannot run.")
# else:
#     # Links that make up the primary path
#     primary_links = [
#         (original_path[i], original_path[i + 1])
#         for i in range(len(original_path) - 1)
#     ]

#     protected_link = st.selectbox(
#         "Assume this primary-path link fails:",
#         [f"{u}-{v}" for u, v in primary_links],
#         index=0,  # default = source → next hop
#         key="protected_link_select",
#         help=(
#             "The backup path is computed on the topology with this link "
#             "removed, i.e. the same way an FRR / LFA repair would be "
#             "calculated for that specific link."
#         ),
#     )

#     u, v = protected_link.split("-")

#     # Build the topology used for the backup calculation
#     G_backup = G.copy()
#     if G_backup.has_edge(u, v):
#         G_backup.remove_edge(u, v)

#     backup_path, backup_cost = shortest_path_stable(
#     G_backup, source, destination, weight="weight"
#     )

# # ---- Display results ------------------------------------------------
# if (
#     source != destination
#     and original_path is not None
#     and protected_link is not None
# ):
#     if backup_path is None:
#         st.error(
#             f"No backup path exists when **{protected_link}** fails. "
#             "The destination becomes unreachable — this link has no "
#             "local repair."
#         )
#     else:
#         col1, col2, col3 = st.columns(3)
#         col1.metric("Primary Path Cost", original_cost)
#         col2.metric("Backup Path Cost", backup_cost)
#         col3.metric(
#             "Extra Cost",
#             backup_cost - original_cost,
#             delta_color="inverse",
#         )

#         st.write("**Primary Path:**", " → ".join(original_path))
#         st.write("**Backup Path:**", " → ".join(backup_path))
#         st.caption(
#             f"Backup computed on the topology with **{protected_link}** removed "
#             "(default: first hop of the primary path)."
#         )

#         # Link-disjointness check
#         primary_set = {
#             frozenset(e) for e in zip(original_path[:-1], original_path[1:])
#         }
#         backup_set = {
#             frozenset(e) for e in zip(backup_path[:-1], backup_path[1:])
#         }
#         shared = primary_set & backup_set

#         if not shared:
#             st.success(
#                 "Backup path is fully link-disjoint from the primary path "
#                 "— it survives a failure of any primary-path link."
#             )
#         else:
#             shared_str = ", ".join(
#                 f"{a}-{b}" for a, b in (tuple(s) for s in shared)
#             )
#             st.warning(
#                 f"Backup shares the following link(s) with the primary: "
#                 f"{shared_str}. It only protects against failure of "
#                 f"**{protected_link}**; those shared links would still take "
#                 "the backup down."
#             )

#         # Optional: visualize the backup
#         with st.expander("Visualize primary vs backup paths"):
#             fig2, ax2 = plt.subplots(figsize=(11, 5))

#             nx.draw_networkx_nodes(
#                 G, POSITIONS, node_size=1400,
#                 node_color=[
#                     "#B7E4C7" if n == source
#                     else "#FFD6A5" if n == destination
#                     else "#DCE6F1"
#                     for n in G.nodes()
#                 ],
#                 ax=ax2,
#             )
#             nx.draw_networkx_labels(G, POSITIONS, font_size=11, ax=ax2)

#             all_edges = list(G.edges())
#             primary_edges = [
#                 e for e in all_edges if frozenset(e) in primary_set
#             ]
#             backup_edges = [
#                 e for e in all_edges if frozenset(e) in backup_set
#             ]
#             other_edges = [
#                 e for e in all_edges
#                 if frozenset(e) not in primary_set | backup_set
#             ]

#             nx.draw_networkx_edges(
#                 G, POSITIONS, edgelist=other_edges,
#                 edge_color="#C8C8C8", width=1.5, ax=ax2,
#             )
#             nx.draw_networkx_edges(
#                 G, POSITIONS, edgelist=primary_edges,
#                 edge_color="green", width=4, ax=ax2,
#                 label="Primary",
#             )
#             nx.draw_networkx_edges(
#                 G, POSITIONS, edgelist=backup_edges,
#                 edge_color="orange", width=4, style="dotted", ax=ax2,
#                 label="Backup",
#             )

#             nx.draw_networkx_edge_labels(
#                 G, POSITIONS,
#                 edge_labels=nx.get_edge_attributes(G, "weight"),
#                 font_size=10, ax=ax2,
#             )
#             ax2.set_axis_off()
#             st.pyplot(fig2)
#             plt.close(fig2)
            
            
# # --------------------------------------------------
# # 10. Failure Impact Analyzer
# # --------------------------------------------------

# st.divider()
# st.header("10. Failure Impact Analyzer")
# st.caption(
#     "Every link in the baseline topology is failed one at a time. "
#     "For the current source → destination pair we report whether the "
#     "destination stays reachable, whether the shortest path changes, "
#     "and how much the cost increases. This analysis always runs against "
#     "the baseline topology, independent of the 'Simulate Link Failure' "
#     "selection above."
# )

# if source == destination:
#     st.info("Pick two different routers to run failure analysis.")
# elif original_path is None:
#     st.error("No baseline path exists, so failure analysis cannot run.")
# else:
#     impact_rows = []

#     for u, v in sorted(G.edges()):
#         G_test = G.copy()
#         G_test.remove_edge(u, v)

#         new_path, new_cost = shortest_path_stable(
#             G_test, source, destination, weight="weight"
#         )

#         if new_path is None:
#             status = "🔴 Disconnected"
#             cost_delta = None
#             hops = None
#             path_str = "—"
#         else:
#             hops = len(new_path) - 1
#             cost_delta = new_cost - original_cost
#             path_str = " → ".join(new_path)
#             if new_path == original_path:
#                 status = "🟢 No change"
#             else:
#                 status = "🟡 Rerouted"

#         impact_rows.append({
#             "Failed Link": f"{u}-{v}",
#             "Link Cost": G[u][v]["weight"],
#             "Status": status,
#             "New Cost": new_cost,
#             "Δ Cost": cost_delta,
#             "Hops": hops,
#             "New Path": path_str,
#         })

#     # ---- Summary strip --------------------------------------------
#     total = len(impact_rows)
#     disconnected = sum(1 for r in impact_rows if r["Status"] == "🔴 Disconnected")
#     unchanged    = sum(1 for r in impact_rows if r["Status"] == "🟢 No change")
#     rerouted     = sum(1 for r in impact_rows if r["Status"] == "🟡 Rerouted")

#     m1, m2, m3, m4 = st.columns(4)
#     m1.metric("Links Tested", total)
#     m2.metric("Disconnects", disconnected)
#     m3.metric("Reroutes", rerouted)
#     m4.metric("No Change", unchanged)

#     # ---- Detailed table -------------------------------------------
#     st.dataframe(
#         impact_rows,
#         use_container_width=True,
#         hide_index=True,
#     )

#     # ---- Headline verdict -----------------------------------------
#     if disconnected:
#         critical = [
#             r["Failed Link"] for r in impact_rows
#             if r["Status"] == "🔴 Disconnected"
#         ]
#         st.warning(
#             f"**{disconnected} critical link(s)** disconnect {destination} "
#             f"from {source}: {', '.join(critical)}"
#         )
#     else:
#         st.success(
#             f"The topology is **1-link resilient** between {source} and "
#             f"{destination}: no single link failure disconnects them."
#         )
        
        
        
# # --------------------------------------------------
# # 11. Link-Disjoint Backup Path
# # --------------------------------------------------

# st.divider()
# st.header("11. Link-Disjoint Backup Path")
# st.caption(
#     "Unlike Section 9 (per-link repair), this finds a backup that shares "
#     "**zero** links with the primary path — true path diversity. "
#     "Computed on the baseline topology."
# )

# if source == destination:
#     st.info("Pick two different routers.")
# elif original_path is None or len(original_path) < 2:
#     st.error("No primary path exists, so no disjoint backup can be computed.")
# else:
#     primary_edges = list(zip(original_path[:-1], original_path[1:]))

#     # Remove every primary-path edge, then look for the shortest path
#     # in what remains. Any path found is disjoint from the primary by
#     # construction.
#     G_disjoint = G.copy()
#     for u, v in primary_edges:
#         if G_disjoint.has_edge(u, v):
#             G_disjoint.remove_edge(u, v)

#     disjoint_path, disjoint_cost = shortest_path_stable(
#         G_disjoint, source, destination, weight="weight"
#     )

#     if disjoint_path is None:
#         st.warning(
#             f"No link-disjoint backup exists between **{source}** and "
#             f"**{destination}**. Every alternate path shares at least one "
#             "link with the primary."
#         )
#     else:
#         col1, col2, col3 = st.columns(3)
#         col1.metric("Primary Cost", original_cost)
#         col2.metric("Disjoint Backup Cost", disjoint_cost)
#         col3.metric(
#             "Extra Cost",
#             disjoint_cost - original_cost,
#             delta_color="inverse",
#         )

#         st.write("**Primary Path:**", " → ".join(original_path))
#         st.write("**Disjoint Backup:**", " → ".join(disjoint_path))

#         st.success(
#             "Backup shares **zero** links with the primary. It survives "
#             "failure of any single primary-path link."
#         )

#         # ---- Visualization -----------------------------------------
#         with st.expander("Visualize primary vs link-disjoint backup"):
#             fig3, ax3 = plt.subplots(figsize=(11, 5))

#             primary_set = {frozenset(e) for e in primary_edges}
#             disjoint_set = {
#                 frozenset(e)
#                 for e in zip(disjoint_path[:-1], disjoint_path[1:])
#             }

#             nx.draw_networkx_nodes(
#                 G, POSITIONS, node_size=1400,
#                 node_color=[
#                     "#B7E4C7" if n == source
#                     else "#FFD6A5" if n == destination
#                     else "#DCE6F1"
#                     for n in G.nodes()
#                 ],
#                 ax=ax3,
#             )
#             nx.draw_networkx_labels(G, POSITIONS, font_size=11, ax=ax3)

#             other = [
#                 e for e in G.edges()
#                 if frozenset(e) not in primary_set | disjoint_set
#             ]
#             primary_edges_draw = [
#                 e for e in G.edges() if frozenset(e) in primary_set
#             ]
#             disjoint_edges_draw = [
#                 e for e in G.edges() if frozenset(e) in disjoint_set
#             ]

#             nx.draw_networkx_edges(
#                 G, POSITIONS, edgelist=other,
#                 edge_color="#C8C8C8", width=1.5, ax=ax3,
#             )
#             nx.draw_networkx_edges(
#                 G, POSITIONS, edgelist=primary_edges_draw,
#                 edge_color="green", width=4, ax=ax3,
#             )
#             nx.draw_networkx_edges(
#                 G, POSITIONS, edgelist=disjoint_edges_draw,
#                 edge_color="orange", width=4, style="dashed", ax=ax3,
#             )
#             nx.draw_networkx_edge_labels(
#                 G, POSITIONS,
#                 edge_labels=nx.get_edge_attributes(G, "weight"),
#                 font_size=10, ax=ax3,
#             )
#             ax3.set_axis_off()
#             st.pyplot(fig3)
#             plt.close(fig3)
            
            
            
# # --------------------------------------------------
# # 12. Equal-Cost Multipath (ECMP)
# # --------------------------------------------------

# st.divider()
# st.header("12. Equal-Cost Multipath (ECMP)")
# st.caption(
#     "All shortest paths between source and destination on the baseline "
#     "topology. When more than one exists, a link-state router installs "
#     "all of them and load-balances traffic across them."
# )

# if source == destination:
#     st.info("Pick two different routers.")
# elif original_path is None:
#     st.error("No baseline path exists, so ECMP cannot be evaluated.")
# else:
#     # Enumerate all simple paths, keep those matching the min cost.
#     # Iteration order is not guaranteed, so we sort at the end for stable output.
#     candidates = []
#     for p in nx.all_simple_paths(G, source, destination):
#         cost = sum(
#             G[p[i]][p[i + 1]]["weight"] for i in range(len(p) - 1)
#         )
#         if cost == original_cost:
#             candidates.append((tuple(p), cost))

#     # Deduplicate (defensive) and sort lexicographically for deterministic output.
#     ecmp_paths = sorted({p for p, _ in candidates})

#     st.metric("Equal-cost paths found", len(ecmp_paths))
#     st.write("**Shortest path cost:**", original_cost)

#     if len(ecmp_paths) == 1:
#         st.info(
#             "Only one shortest path exists between these routers — "
#             "no ECMP at this destination."
#         )
#     else:
#         st.success(
#             f"{len(ecmp_paths)} equal-cost paths. A router would load-balance "
#             "across all of them."
#         )

#     # Table of paths
#     ecmp_rows = []
#     for p in ecmp_paths:
#         ecmp_rows.append({
#             "Path": " → ".join(p),
#             "Hops": len(p) - 1,
#             "Cost": original_cost,
#         })

#     st.dataframe(ecmp_rows, use_container_width=True, hide_index=True)

#     # Shared-link annotation: what do all ECMP paths have in common?
#     if len(ecmp_paths) > 1:
#         edge_sets = [
#             {frozenset(e) for e in zip(p[:-1], p[1:])}
#             for p in ecmp_paths
#         ]
#         common = set.intersection(*edge_sets)
#         if common:
#             common_str = ", ".join(
#                 f"{a}-{b}" for a, b in (tuple(s) for s in common)
#             )
#             st.caption(
#                 f"Links common to every ECMP path: **{common_str}**. "
#                 "These are single points of failure even under load-balancing."
#             )
#         else:
#             st.caption(
#                 "No link is common to all ECMP paths — the destination "
#                 "survives any single-link failure under ECMP."
#             )
            
# # --------------------------------------------------
# # 13. LFA / Link-Protection Coverage
# # --------------------------------------------------

# st.divider()
# st.header("13. LFA / Link-Protection Coverage")
# st.caption(
#     "For each primary-path link (u, v), this checks whether the upstream "
#     "router u has an alternate neighbor that can reach the destination "
#     "without transiting u. That is the local-repair condition used by "
#     "LFA / FRR. Computed on the baseline topology, per router."
# )


# def find_lfas(graph, u, failed_neighbor, destination):
#     """
#     Return a list of (next_hop, path_from_next_hop, cost_from_next_hop)
#     for neighbors of u (excluding failed_neighbor) that can reach
#     destination without transiting u.

#     Removing u entirely guarantees loop-free repair: whatever path the
#     next hop takes to the destination, it cannot route back through u.
#     """
#     G_fail = graph.copy()
#     if G_fail.has_edge(u, failed_neighbor):
#         G_fail.remove_edge(u, failed_neighbor)
#     if u in G_fail:
#         G_fail.remove_node(u)

#     result = []
#     for n in graph.neighbors(u):
#         if n == failed_neighbor:
#             continue
#         if n not in G_fail or destination not in G_fail:
#             continue
#         path, cost = shortest_path_stable(
#             G_fail, n, destination, weight="weight"
#         )
#         if path is not None:
#             result.append((n, path, cost))
#     return result


# if source == destination:
#     st.info("Pick two different routers.")
# elif original_path is None or len(original_path) < 2:
#     st.error("No primary path exists.")
# else:
#     primary_edges = list(zip(original_path[:-1], original_path[1:]))

#     lfa_rows = []
#     covered = 0

#     for u, v in primary_edges:
#         lfas = find_lfas(G, u, v, destination)

#         if not lfas:
#             status = "🔴 No LFA"
#             best = None
#         else:
#             covered += 1
#             status = "🟢 Protected"
#             # Prefer the smallest repair cost; break ties by next-hop name
#             # so output is stable across reloads.
#             best = min(lfas, key=lambda x: (x[2], x[0]))

#         repair_path = None
#         repair_cost_from_u = None
#         if best:
#             n, path_from_n, cost_from_n = best
#             repair_path = [u] + list(path_from_n)
#             repair_cost_from_u = G[u][n]["weight"] + cost_from_n

#         lfa_rows.append({
#             "Protected Link": f"{u}-{v}",
#             "Upstream": u,
#             "Status": status,
#             "# LFAs": len(lfas),
#             "LFA Next-Hop": best[0] if best else "—",
#             "Repair Path (from u)": (
#                 " → ".join(repair_path) if repair_path else "—"
#             ),
#             "Repair Cost (from u)": repair_cost_from_u,
#         })

#     total = len(primary_edges)
#     coverage_pct = (covered / total * 100) if total else 0

#     m1, m2, m3 = st.columns(3)
#     m1.metric("Primary-path links", total)
#     m2.metric("Protected by LFA", covered)
#     m3.metric("Coverage", f"{coverage_pct:.0f}%")

#     st.dataframe(lfa_rows, use_container_width=True, hide_index=True)

#     if covered == total:
#         st.success(
#             "Full LFA coverage: every primary-path link has a local "
#             "repair. FRR can protect the entire path without waiting for "
#             "IGP reconvergence."
#         )
#     elif covered == 0:
#         st.error(
#             "No LFA coverage: no primary-path link has a local repair. "
#             "Every failure would require full IGP reconvergence."
#         )
#     else:
#         uncovered = [
#             r["Protected Link"] for r in lfa_rows if r["Status"] == "🔴 No LFA"
#         ]
#         st.warning(
#             f"Partial coverage: {total - covered} of {total} primary-path "
#             f"link(s) have no LFA and would require full reconvergence — "
#             f"{', '.join(uncovered)}."
#         )

#     st.caption(
#         "Repair paths are local to each upstream router — they are what the "
#         "router would install in its FIB *before* any failure. This is why "
#         "the numbers here can differ from Section 9, which recomputes a "
#         "shortest path from the source after removing the link."
#     )
    
#     # --------------------------------------------------
# # 14. IS-IS-style SPF Computation
# # --------------------------------------------------

# st.divider()
# st.header("14. IS-IS-style SPF Computation")
# st.caption(
#     "Dijkstra's algorithm traced from the source router using the same "
#     "vocabulary a link-state IGP (IS-IS, OSPF) uses: tentative distance, "
#     "candidate list, predecessor, finalization. In a real IGP every router "
#     "runs this independently, rooted at itself."
# )


# def spf_trace(graph, root, weight="weight"):
#     """
#     Run Dijkstra from `root` and return:
#       steps   — one dict per finalized node, with relaxations and TD snapshot
#       tent    — final tentative distances {node: cost}
#       pred    — predecessor tree {node: prev_node}
#     Tie-break: smaller (cost, node_name) wins, matching shortest_path_stable.
#     """
#     tent = {root: 0}
#     pred = {root: None}
#     visited = set()
#     steps = []
#     candidates = [(0, root)]   # (cost, node) — sorted manually for determinism

#     while candidates:
#         candidates.sort()
#         cost, node = candidates.pop(0)

#         if node in visited:
#             continue
#         visited.add(node)

#         relaxations = []

#         for nb in sorted(graph.neighbors(node)):
#             if nb in visited:
#                 continue
#             w = graph[node][nb].get(weight, 1)
#             new_cost = cost + w
#             old = tent.get(nb, float("inf"))

#             if new_cost < old:
#                 tent[nb] = new_cost
#                 pred[nb] = node
#                 candidates.append((new_cost, nb))
#                 relaxations.append({
#                     "neighbor": nb, "edge_cost": w,
#                     "old_td": old, "new_td": new_cost,
#                     "action": "NEW" if old == float("inf") else "UPDATE",
#                 })
#             elif new_cost == old:
#                 # Tie — prefer smaller predecessor name for stable output
#                 if pred.get(nb) is None or node < pred[nb]:
#                     pred[nb] = node
#                 relaxations.append({
#                     "neighbor": nb, "edge_cost": w,
#                     "old_td": old, "new_td": new_cost,
#                     "action": "TIE (kept smaller pred)",
#                 })
#             else:
#                 relaxations.append({
#                     "neighbor": nb, "edge_cost": w,
#                     "old_td": old, "new_td": new_cost,
#                     "action": "NO CHANGE",
#                 })

#         # Reconstruct the path source → node from the predecessor chain
#         chain = []
#         c = node
#         while c is not None:
#             chain.append(c)
#             c = pred.get(c)
#         chain.reverse()

#         steps.append({
#             "step": len(steps) + 1,
#             "finalized": node,
#             "cost": cost,
#             "path": chain,
#             "relaxations": relaxations,
#         })

#     return steps, tent, pred


# if source == destination:
#     st.info("Pick two different routers.")
# else:
#     steps, final_dist, final_pred = spf_trace(G, source)

#     # ---- Step summary ------------------------------------------
#     st.markdown(
#         f"**Finalization order** — shortest distances from **{source}** "
#         "are confirmed in this order:"
#     )
#     summary_rows = [
#         {
#             "Step": s["step"],
#             "Finalized": s["finalized"],
#             "Cost": s["cost"],
#             "Path from source": " → ".join(s["path"]),
#         }
#         for s in steps
#     ]
#     st.dataframe(summary_rows, use_container_width=True, hide_index=True)

#     # ---- Full relaxation trace ---------------------------------
#     with st.expander("Full relaxation trace (step by step)"):
#         for s in steps:
#             st.markdown(
#                 f"**Step {s['step']}** — finalize **{s['finalized']}** "
#                 f"(cost `{s['cost']}`, path `{' → '.join(s['path'])}`)"
#             )
#             if not s["relaxations"]:
#                 st.caption("No unvisited neighbors to relax.")
#             else:
#                 rel_rows = []
#                 for r in s["relaxations"]:
#                     old_str = "∞" if r["old_td"] == float("inf") else str(r["old_td"])
#                     new_str = (
#                         old_str if r["action"] == "NO CHANGE" else str(r["new_td"])
#                     )
#                     rel_rows.append({
#                         "Neighbor": r["neighbor"],
#                         "Edge Cost": r["edge_cost"],
#                         "Old TD": old_str,
#                         "New TD": new_str,
#                         "Action": r["action"],
#                     })
#                 st.dataframe(rel_rows, use_container_width=True, hide_index=True)
#             st.divider()

#     # ---- Resulting routing table (SPT) -------------------------
#     st.markdown(
#         f"**Routing table computed by {source}** "
#         "(shortest-path tree — next hop for every destination):"
#     )

#     rt_rows = []
#     for node in sorted(G.nodes()):
#         if node == source:
#             continue
#         if node not in final_dist:
#             rt_rows.append({
#                 "Destination": node,
#                 "Cost": "unreachable",
#                 "Next-Hop": "—",
#                 "Full Path": "—",
#             })
#             continue

#         chain = []
#         c = node
#         while c is not None:
#             chain.append(c)
#             c = final_pred.get(c)
#         chain.reverse()
#         next_hop = chain[1] if len(chain) > 1 else "—"

#         rt_rows.append({
#             "Destination": node,
#             "Cost": final_dist[node],
#             "Next-Hop": next_hop,
#             "Full Path": " → ".join(chain),
#         })

#     st.dataframe(rt_rows, use_container_width=True, hide_index=True)

#     st.caption(
#         "The SPF run here uses the same tie-break as `shortest_path_stable`, "
#         "so the path chosen for the current target matches Sections 5–13 "
#         "exactly."
#     )