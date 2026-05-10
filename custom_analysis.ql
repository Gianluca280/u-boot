/**
 * @name Network byte swap flows to memcpy
 * @description Traccia il flusso di dati dai macro ntoh alla dimensione di una memcpy
 * @kind path-problem
 * @id cpp/taint-analysis-custom
 * @problem.severity warning
 * @precision high
 */

import cpp
import semmle.code.cpp.dataflow.TaintTracking
import MyTaint::PathGraph

class NetworkByteSwap extends Expr {
  NetworkByteSwap() {
    exists(MacroInvocation mi |
      mi.getMacro().getName() in ["ntohs", "ntohl", "ntohll"] and
      this = mi.getExpr()
    )
  }
}

module MyConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    source.asExpr() instanceof NetworkByteSwap
  }

  predicate isSink(DataFlow::Node sink) {
    exists(FunctionCall fc |
      fc.getTarget().getName() = "memcpy" and
      sink.asExpr() = fc.getArgument(2)
    )
  }

  predicate isBarrier(DataFlow::Node node) {
    exists(IfStmt is | 
      node.asExpr() = is.getControllingExpr().getAChild*()
    )
  }
}

module MyTaint = TaintTracking::Global<MyConfig>;

from MyTaint::PathNode source, MyTaint::PathNode sink
where MyTaint::flowPath(source, sink) 
select sink.getNode(), source, sink, "Network byte swap flows to memcpy"
