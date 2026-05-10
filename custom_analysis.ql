/**
 * @name Network byte swap flows to memcpy
 * @description Taint tracking analysis
 * @kind path-problem
 * @id cpp/taint-analysis-custom
 * @problem.severity warning
 */

import cpp
import semmle.code.cpp.dataflow.TaintTracking
import MyTaint::PathGraph

module MyConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    exists(MacroInvocation mi |
      mi.getMacro().getName() in ["ntohs", "ntohl", "ntohll"] and
      source.asExpr() = mi.getExpr()
    )
  }

  predicate isSink(DataFlow::Node sink) {
    exists(FunctionCall fc |
      fc.getTarget().getName() = "memcpy" and
      sink.asExpr() = fc.getArgument(2)
    )
  }
}

module MyTaint = TaintTracking::Global<MyConfig>;

from MyTaint::PathNode source, MyTaint::PathNode sink
where MyTaint::flowPath(source, sink)
select sink.getNode(), source, sink, "Network byte swap flows to memcpy"
