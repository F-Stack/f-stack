/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2020 Marvell International Ltd.
 */

#include <fnmatch.h>
#include <stdbool.h>
#include <stdlib.h>

#include <rte_common.h>
#include <rte_debug.h>
#include <rte_errno.h>
#include <rte_malloc.h>
#include <rte_memzone.h>
#include <rte_spinlock.h>
#include <rte_string_fns.h>

#include "graph_private.h"

static struct graph_head graph_list = STAILQ_HEAD_INITIALIZER(graph_list);
static rte_spinlock_t graph_lock = RTE_SPINLOCK_INITIALIZER;

/* Private functions */
static struct graph *
graph_from_id(rte_graph_t id)
{
	struct graph *graph;
	STAILQ_FOREACH(graph, &graph_list, next) {
		if (graph->id == id)
			return graph;
	}
	rte_errno = EINVAL;
	return NULL;
}

static rte_graph_t
graph_next_free_id(void)
{
	struct graph *graph;
	rte_graph_t id = 0;

	STAILQ_FOREACH(graph, &graph_list, next) {
		if (id < graph->id)
			break;
		id = graph->id + 1;
	}

	return id;
}

static void
graph_insert_ordered(struct graph *graph)
{
	struct graph *after, *g;

	after = NULL;
	STAILQ_FOREACH(g, &graph_list, next) {
		if (g->id < graph->id)
			after = g;
		else if (g->id > graph->id)
			break;
	}
	if (after == NULL) {
		STAILQ_INSERT_HEAD(&graph_list, graph, next);
	} else {
		STAILQ_INSERT_AFTER(&graph_list, after, graph, next);
	}
}

struct graph_head *
graph_list_head_get(void)
{
	return &graph_list;
}

void
graph_spinlock_lock(void)
{
	rte_spinlock_lock(&graph_lock);
}

void
graph_spinlock_unlock(void)
{
	rte_spinlock_unlock(&graph_lock);
}

static int
graph_node_add(struct graph *graph, struct node *node)
{
	struct graph_node *graph_node;
	size_t sz;

	/* Skip the duplicate nodes */
	STAILQ_FOREACH(graph_node, &graph->node_list, next)
		if (strncmp(node->name, graph_node->node->name,
			    RTE_NODE_NAMESIZE) == 0)
			return 0;

	/* Allocate new graph node object */
	sz = sizeof(*graph_node) + node->nb_edges * sizeof(struct node *);
	graph_node = calloc(1, sz);

	if (graph_node == NULL)
		SET_ERR_JMP(ENOMEM, free, "Failed to calloc %s object",
			    node->name);

	/* Initialize the graph node */
	graph_node->node = node;

	/* Add to graph node list */
	STAILQ_INSERT_TAIL(&graph->node_list, graph_node, next);
	return 0;

free:
	free(graph_node);
	return -rte_errno;
}

static struct graph_node *
node_to_graph_node(struct graph *graph, struct node *node)
{
	struct graph_node *graph_node;

	STAILQ_FOREACH(graph_node, &graph->node_list, next)
		if (graph_node->node == node)
			return graph_node;

	SET_ERR_JMP(ENODEV, fail, "Found isolated node %s", node->name);
fail:
	return NULL;
}

static int
graph_node_edges_add(struct graph *graph)
{
	struct graph_node *graph_node;
	struct node *adjacency;
	const char *next;
	rte_edge_t i;

	STAILQ_FOREACH(graph_node, &graph->node_list, next) {
		for (i = 0; i < graph_node->node->nb_edges; i++) {
			next = graph_node->node->next_nodes[i];
			adjacency = node_from_name(next);
			if (adjacency == NULL)
				SET_ERR_JMP(EINVAL, fail,
					    "Node %s not registered", next);
			if (graph_node_add(graph, adjacency))
				goto fail;
		}
	}
	return 0;
fail:
	return -rte_errno;
}

static int
graph_adjacency_list_update(struct graph *graph)
{
	struct graph_node *graph_node, *tmp;
	struct node *adjacency;
	const char *next;
	rte_edge_t i;

	STAILQ_FOREACH(graph_node, &graph->node_list, next) {
		for (i = 0; i < graph_node->node->nb_edges; i++) {
			next = graph_node->node->next_nodes[i];
			adjacency = node_from_name(next);
			if (adjacency == NULL)
				SET_ERR_JMP(EINVAL, fail,
					    "Node %s not registered", next);
			tmp = node_to_graph_node(graph, adjacency);
			if (tmp == NULL)
				goto fail;
			graph_node->adjacency_list[i] = tmp;
		}
	}

	return 0;
fail:
	return -rte_errno;
}

static int
expand_pattern_to_node(struct graph *graph, const char *pattern)
{
	struct node_head *node_head = node_list_head_get();
	bool found = false;
	struct node *node;

	/* Check for pattern match */
	STAILQ_FOREACH(node, node_head, next) {
		if (fnmatch(pattern, node->name, 0) == 0) {
			if (graph_node_add(graph, node))
				goto fail;
			found = true;
		}
	}
	if (found == false)
		SET_ERR_JMP(EFAULT, fail, "Pattern %s node not found", pattern);

	return 0;
fail:
	return -rte_errno;
}

static void
graph_cleanup(struct graph *graph)
{
	struct graph_node *graph_node;

	while (!STAILQ_EMPTY(&graph->node_list)) {
		graph_node = STAILQ_FIRST(&graph->node_list);
		STAILQ_REMOVE_HEAD(&graph->node_list, next);
		free(graph_node);
	}
}

static int
graph_node_init(struct graph *graph)
{
	struct graph_node *graph_node;
	const char *name;
	int rc;

	STAILQ_FOREACH(graph_node, &graph->node_list, next) {
		if (graph_node->node->init) {
			name = graph_node->node->name;
			rc = graph_node->node->init(
				graph->graph,
				graph_node_name_to_ptr(graph->graph, name));
			if (rc)
				SET_ERR_JMP(rc, err, "Node %s init() failed",
					    name);
		}
	}

	return 0;
err:
	return -rte_errno;
}

static void
graph_node_fini(struct graph *graph)
{
	struct graph_node *graph_node;

	STAILQ_FOREACH(graph_node, &graph->node_list, next)
		if (graph_node->node->fini)
			graph_node->node->fini(
				graph->graph,
				graph_node_name_to_ptr(graph->graph,
						       graph_node->node->name));
}

static struct rte_graph *
graph_mem_fixup_node_ctx(struct rte_graph *graph)
{
	struct rte_node *node;
	struct node *node_db;
	rte_graph_off_t off;
	rte_node_t count;
	const char *name;

	rte_graph_foreach_node(count, off, graph, node) {
		if (node->parent_id == RTE_NODE_ID_INVALID) /* Static node */
			name = node->name;
		else /* Cloned node */
			name = node->parent;

		node_db = node_from_name(name);
		if (node_db == NULL)
			SET_ERR_JMP(ENOLINK, fail, "Node %s not found", name);
		node->process = node_db->process;
	}

	return graph;
fail:
	return NULL;
}

static struct rte_graph *
graph_mem_fixup_secondary(struct rte_graph *graph)
{
	if (graph == NULL || rte_eal_process_type() == RTE_PROC_PRIMARY)
		return graph;

	return graph_mem_fixup_node_ctx(graph);
}

struct rte_graph *
rte_graph_lookup(const char *name)
{
	const struct rte_memzone *mz;
	struct rte_graph *rc = NULL;

	mz = rte_memzone_lookup(name);
	if (mz)
		rc = mz->addr;

	return graph_mem_fixup_secondary(rc);
}

rte_graph_t
rte_graph_create(const char *name, struct rte_graph_param *prm)
{
	rte_node_t src_node_count;
	struct graph *graph;
	const char *pattern;
	uint16_t i;

	graph_spinlock_lock();

	/* Check arguments sanity */
	if (prm == NULL)
		SET_ERR_JMP(EINVAL, fail, "Param should not be NULL");

	if (name == NULL)
		SET_ERR_JMP(EINVAL, fail, "Graph name should not be NULL");

	/* Check for existence of duplicate graph */
	STAILQ_FOREACH(graph, &graph_list, next)
		if (strncmp(name, graph->name, RTE_GRAPH_NAMESIZE) == 0)
			SET_ERR_JMP(EEXIST, fail, "Found duplicate graph %s",
				    name);

	/* Create graph object */
	graph = calloc(1, sizeof(*graph));
	if (graph == NULL)
		SET_ERR_JMP(ENOMEM, fail, "Failed to calloc graph object");

	/* Initialize the graph object */
	STAILQ_INIT(&graph->node_list);
	if (rte_strscpy(graph->name, name, RTE_GRAPH_NAMESIZE) < 0)
		SET_ERR_JMP(E2BIG, free, "Too big name=%s", name);

	/* Expand node pattern and add the nodes to the graph */
	for (i = 0; i < prm->nb_node_patterns; i++) {
		pattern = prm->node_patterns[i];
		if (expand_pattern_to_node(graph, pattern))
			goto graph_cleanup;
	}

	/* Go over all the nodes edges and add them to the graph */
	if (graph_node_edges_add(graph))
		goto graph_cleanup;

	/* Update adjacency list of all nodes in the graph */
	if (graph_adjacency_list_update(graph))
		goto graph_cleanup;

	/* Make sure at least a source node present in the graph */
	src_node_count = graph_src_nodes_count(graph);
	if (src_node_count == 0)
		goto graph_cleanup;

	/* Make sure no node is pointing to source node */
	if (graph_node_has_edge_to_src_node(graph))
		goto graph_cleanup;

	/* Don't allow node has loop to self */
	if (graph_node_has_loop_edge(graph))
		goto graph_cleanup;

	/* Do BFS from src nodes on the graph to find isolated nodes */
	if (graph_has_isolated_node(graph))
		goto graph_cleanup;

	/* Initialize graph object */
	graph->socket = prm->socket_id;
	graph->src_node_count = src_node_count;
	graph->node_count = graph_nodes_count(graph);
	graph->id = graph_next_free_id();

	/* Allocate the Graph fast path memory and populate the data */
	if (graph_fp_mem_create(graph))
		goto graph_cleanup;

	/* Call init() of the all the nodes in the graph */
	if (graph_node_init(graph))
		goto graph_mem_destroy;

	/* All good, Lets add the graph to the list */
	graph_insert_ordered(graph);

	graph_spinlock_unlock();
	return graph->id;

graph_mem_destroy:
	graph_fp_mem_destroy(graph);
graph_cleanup:
	graph_cleanup(graph);
free:
	free(graph);
fail:
	graph_spinlock_unlock();
	return RTE_GRAPH_ID_INVALID;
}

int
rte_graph_destroy(rte_graph_t id)
{
	struct graph *graph, *tmp;
	int rc = -ENOENT;

	graph_spinlock_lock();

	graph = STAILQ_FIRST(&graph_list);
	while (graph != NULL) {
		tmp = STAILQ_NEXT(graph, next);
		if (graph->id == id) {
			/* Call fini() of the all the nodes in the graph */
			graph_node_fini(graph);
			/* Destroy graph fast path memory */
			rc = graph_fp_mem_destroy(graph);
			if (rc)
				SET_ERR_JMP(rc, done, "Graph %s destroy failed",
					    graph->name);

			graph_cleanup(graph);
			STAILQ_REMOVE(&graph_list, graph, graph, next);
			free(graph);
			goto done;
		}
		graph = tmp;
	}
done:
	graph_spinlock_unlock();
	return rc;
}

rte_graph_t
rte_graph_from_name(const char *name)
{
	struct graph *graph;

	STAILQ_FOREACH(graph, &graph_list, next)
		if (strncmp(graph->name, name, RTE_GRAPH_NAMESIZE) == 0)
			return graph->id;

	return RTE_GRAPH_ID_INVALID;
}

char *
rte_graph_id_to_name(rte_graph_t id)
{
	struct graph *graph;

	if (graph_from_id(id) == NULL)
		goto fail;
	STAILQ_FOREACH(graph, &graph_list, next)
		if (graph->id == id)
			return graph->name;

fail:
	return NULL;
}

struct rte_node *
rte_graph_node_get(rte_graph_t gid, uint32_t nid)
{
	struct rte_node *node;
	struct graph *graph;
	rte_graph_off_t off;
	rte_node_t count;

	if (graph_from_id(gid) == NULL)
		goto fail;
	STAILQ_FOREACH(graph, &graph_list, next)
		if (graph->id == gid) {
			rte_graph_foreach_node(count, off, graph->graph,
						node) {
				if (node->id == nid)
					return node;
			}
			break;
		}
fail:
	return NULL;
}

struct rte_node *
rte_graph_node_get_by_name(const char *graph_name, const char *node_name)
{
	struct rte_node *node;
	struct graph *graph;
	rte_graph_off_t off;
	rte_node_t count;

	STAILQ_FOREACH(graph, &graph_list, next)
		if (!strncmp(graph->name, graph_name, RTE_GRAPH_NAMESIZE)) {
			rte_graph_foreach_node(count, off, graph->graph,
						node) {
				if (!strncmp(node->name, node_name,
					     RTE_NODE_NAMESIZE))
					return node;
			}
			break;
		}

	return NULL;
}

void __rte_noinline
__rte_node_stream_alloc(struct rte_graph *graph, struct rte_node *node)
{
	uint16_t size = node->size;

	RTE_VERIFY(size != UINT16_MAX);
	/* Allocate double amount of size to avoid immediate realloc */
	size = RTE_MIN(UINT16_MAX, RTE_MAX(RTE_GRAPH_BURST_SIZE, size * 2));
	node->objs = rte_realloc_socket(node->objs, size * sizeof(void *),
					RTE_CACHE_LINE_SIZE, graph->socket);
	RTE_VERIFY(node->objs);
	node->size = size;
	node->realloc_count++;
}

void __rte_noinline
__rte_node_stream_alloc_size(struct rte_graph *graph, struct rte_node *node,
			     uint16_t req_size)
{
	uint16_t size = node->size;

	RTE_VERIFY(size != UINT16_MAX);
	/* Allocate double amount of size to avoid immediate realloc */
	size = RTE_MIN(UINT16_MAX, RTE_MAX(RTE_GRAPH_BURST_SIZE, req_size * 2));
	node->objs = rte_realloc_socket(node->objs, size * sizeof(void *),
					RTE_CACHE_LINE_SIZE, graph->socket);
	RTE_VERIFY(node->objs);
	node->size = size;
	node->realloc_count++;
}

static int
graph_to_dot(FILE *f, struct graph *graph)
{
	const char *src_edge_color = " [color=blue]\n";
	const char *edge_color = "\n";
	struct graph_node *graph_node;
	char *node_name;
	rte_edge_t i;
	int rc;

	rc = fprintf(f, "Digraph %s {\n\trankdir=LR;\n", graph->name);
	if (rc < 0)
		goto end;

	STAILQ_FOREACH(graph_node, &graph->node_list, next) {
		node_name = graph_node->node->name;
		for (i = 0; i < graph_node->node->nb_edges; i++) {
			rc = fprintf(f, "\t\"%s\"->\"%s\"%s", node_name,
				     graph_node->adjacency_list[i]->node->name,
				     graph_node->node->flags & RTE_NODE_SOURCE_F
					     ? src_edge_color
					     : edge_color);
			if (rc < 0)
				goto end;
		}
	}
	rc = fprintf(f, "}\n");
	if (rc < 0)
		goto end;

	return 0;
end:
	rte_errno = EBADF;
	return -rte_errno;
}

int
rte_graph_export(const char *name, FILE *f)
{
	struct graph *graph;
	int rc = ENOENT;

	STAILQ_FOREACH(graph, &graph_list, next) {
		if (strncmp(graph->name, name, RTE_GRAPH_NAMESIZE) == 0) {
			rc = graph_to_dot(f, graph);
			goto end;
		}
	}
end:
	return -rc;
}

static void
graph_scan_dump(FILE *f, rte_graph_t id, bool all)
{
	struct graph *graph;

	RTE_VERIFY(f);
	if (graph_from_id(id) == NULL)
		goto fail;

	STAILQ_FOREACH(graph, &graph_list, next) {
		if (all == true) {
			graph_dump(f, graph);
		} else if (graph->id == id) {
			graph_dump(f, graph);
			return;
		}
	}
fail:
	return;
}

void
rte_graph_dump(FILE *f, rte_graph_t id)
{
	graph_scan_dump(f, id, false);
}

void
rte_graph_list_dump(FILE *f)
{
	graph_scan_dump(f, 0, true);
}

rte_graph_t
rte_graph_max_count(void)
{
	struct graph *graph;
	rte_graph_t count = 0;

	STAILQ_FOREACH(graph, &graph_list, next)
		count++;

	return count;
}

RTE_LOG_REGISTER_DEFAULT(rte_graph_logtype, INFO);
