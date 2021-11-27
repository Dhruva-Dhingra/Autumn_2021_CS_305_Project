// Copyright (c) 2015, The Regents of the University of California (Regents)
// See LICENSE.txt for license details

#include <algorithm>
#include <iostream>
#include <vector>
#include <cassert>
#include <parallel/algorithm>
//#include <omp.h>

#include "benchmark.h"
#include "builder.h"
#include "command_line.h"
#include "graph.h"
#include "pvector.h"


/*
GAP Benchmark Suite
Kernel: PageRank (PR)
Author: Scott Beamer


*/


using namespace std;

const int numDataTypes = 5;    
const int IRREGDATA   {0};
const int REGDATA     {1};
const int CSR_OFFSETS {2};
const int CSR_COORDS  {3};
const int FRONTIER    {4};
const int OTHERS      {5};


typedef float ScoreT;
const float kDamp = 0.85;



pvector<ScoreT> PageRankPull(const Graph &g, 
                             int max_iters,
                             double epsilon = 0) {
  const ScoreT init_score = 1.0f / g.num_nodes();
  const ScoreT base_score = (1.0f - kDamp) / g.num_nodes();
  

  pvector<ScoreT> scores(g.num_nodes(), init_score);
  pvector<ScoreT> outgoing_contrib(g.num_nodes());

  //assert(omp_get_max_threads() == 8);

  /* start main computation */
  max_iters = 1; 
  double error;
  for (int iter=0; iter < max_iters; iter++) {
    error = 0;
    //#pragma omp parallel for schedule(static)
    for (NodeID n=0; n < g.num_nodes(); n++)
      outgoing_contrib[n] = scores[n] / g.out_degree(n); 

    
    NodeID numEpochs {256};
    NodeID epochSz = (g.num_nodes() + numEpochs - 1) / numEpochs;
    for (NodeID e = 0; e < numEpochs; ++e)
    {
      NodeID startVtx = e * epochSz;
      NodeID endVtx   = (e + 1) * epochSz;
      if (e == numEpochs - 1)
        endVtx = g.num_nodes();

      //#pragma omp parallel for reduction(+ : error) schedule(dynamic, 64) 
      for (NodeID u = startVtx; u < endVtx; ++u) {
        //int tid = omp_get_thread_num();

        ScoreT incoming_total = 0;
        for (NodeID v : g.in_neigh(u))
          incoming_total += outgoing_contrib[v];
        ScoreT old_score = scores[u];
        scores[u] = base_score + kDamp * incoming_total;
        error += fabs(scores[u] - old_score);
      }
    }


    //printf(" %2d    %lf\n", iter, error);
    if (error < epsilon)
      break;
  }

  pvector<ScoreT> dummy(1);
  return dummy;
}


void PrintTopScores(const Graph &g, const pvector<ScoreT> &scores) {
  vector<pair<NodeID, ScoreT>> score_pairs(g.num_nodes());
  for (NodeID n=0; n < g.num_nodes(); n++) {
    score_pairs[n] = make_pair(n, scores[n]);
  }
  int k = 5;
  vector<pair<ScoreT, NodeID>> top_k = TopK(score_pairs, k);
  k = min(k, static_cast<int>(top_k.size()));
  for (auto kvp : top_k)
    cout << kvp.second << ":" << kvp.first << endl;
}


// Verifies by asserting a single serial iteration in push direction has
//   error < target_error
bool PRVerifier(const Graph &g, const pvector<ScoreT> &scores,
                        double target_error) {
  const ScoreT base_score = (1.0f - kDamp) / g.num_nodes();
  pvector<ScoreT> incomming_sums(g.num_nodes(), 0);
  double error = 0;
  for (NodeID u : g.vertices()) {
    ScoreT outgoing_contrib = scores[u] / g.out_degree(u);
    for (NodeID v : g.out_neigh(u))
      incomming_sums[v] += outgoing_contrib;
  }
  for (NodeID n : g.vertices()) {
    error += fabs(base_score + kDamp * incomming_sums[n] - scores[n]);
    incomming_sums[n] = 0;
  }
  PrintTime("Total Error", error);
  return error < target_error;
}


int main(int argc, char* argv[]) {
  argc = 3;
  argv = new char*[argc];
  argv[0] = (char*)malloc(3 * sizeof(char));
  argv[0][0] = 'p';
  argv[0][1] = 'r';
  argv[0][2] = 0;
  
  argv[1] = (char*)malloc(3 * sizeof(char));
  argv[1][0] = '-';
  argv[1][1] = 'g';
  argv[1][2] = 0;
  
  argv[2] = (char*)malloc(3 * sizeof(char));
  argv[2][0] = '2';
  argv[2][1] = '0';
  argv[2][2] = 0;
  
  CLPageRank cli(argc, argv, "pagerank", 1e-4, 20);
  if (!cli.ParseArgs())
    return -1;
  //omp_set_num_threads(1); 
  Builder b(cli);
  Graph g = b.MakeGraph();
  std::cout << "[GRAPH-STATS] Nodes = " << g.num_nodes() << std::endl;
  std::cout << "[GRAPH-STATS] Edges = " << g.num_edges_directed() << std::endl;

  NodeID vtxPerLine    = 64 / sizeof(ScoreT);
  NodeID numCacheLines = (g.num_nodes() + vtxPerLine - 1) / vtxPerLine;
  NodeID numEpochs     = 256;
  pvector<uint8_t> offsetMatrix(numCacheLines * numEpochs);
  b.makeOffsetMatrix(g, offsetMatrix, vtxPerLine, numEpochs, true); 

  auto offsetsPtr = g.returnOffsetsArray();
  auto coordsPtr  = g.returnCoordsArray();

  PageRankPull(g, cli.max_iters(), cli.tolerance());
  return 0;
}
