#!/bin/sh

# 1st arguement is a CADETS trace file - will create a png
# requires graphviz to be installed

file_name=$(basename -s'.json' $1)

{
echo "digraph $file_name {";
echo "rankdir=\"LR\";"
sed -n -E 's/.*"path": "([ [:alnum:]\\\/_.-]*)".*/"f_\1" [label="\1"];/p' $1 | sort | uniq ;
sed -n -E 's/.*"new_exec": "([ [:alnum:]\\\/_.-]*)".*/"f_\1" [label="\1"];/p' $1 | sort | uniq ;
grep 'write' $1 | sed -n -E 's/.*"event": "[[:alnum:]_-]*:[[:alnum:]_-]*:(.?write[[:alnum:]_-]*):".*"pid": ([[:digit:]]*).*"exec": "([[:alnum:]_-]*)".*"path": "([ [:alnum:]\\\/_.-]*)".*/    p_\2 [label="pid \2", shape="diamond"];\
    "p_\2_\3" [label="{{\3 | p\2}}", shape="record"];\
    "p_\2_\3" -> "f_\4" [label="write", color="saddlebrown"];/p'
grep 'read' $1 | sed -n -E 's/.*"event": "[[:alnum:]_-]*:[[:alnum:]_-]*:(.?read[[:alnum:]_-]*):".*"pid": ([[:digit:]]*).*"exec": "([[:alnum:]_-]*)".*"path": "([ [:alnum:]\\\/_.-]*)".*/    p_\2 [label="pid \2", shape="diamond"];\
    "p_\2_\3" [label="{{\3 | p\2}}", shape="record"];\
    "f_\4" -> "p_\2_\3" [label="read", color="black"];/p'
grep 'mmap' $1 | sed -n -E 's/.*"event": "[[:alnum:]_-]*:[[:alnum:]_-]*:(.?mmap[[:alnum:]_-]*):".*"pid": ([[:digit:]]*).*"exec": "([[:alnum:]_-]*)".*"path": "([ [:alnum:]\\\/_.-]*)".*/    p_\2 [label="pid \2", shape="diamond"];\
    "p_\2_\3" [label="{{\3 | p\2}}", shape="record"];\
    "f_\4" -> "p_\2_\3" [label="mmap", color="black"];/p'
grep 'new_exec' $1 | sed -n -E 's/.*"event": "[[:alnum:]_-]*:[[:alnum:]_-]*:(.?exec[[:alnum:]_-]*):".*"pid": ([[:digit:]]*).*"uid": ([[:digit:]]*).*"exec": "([[:alnum:]_-]*)".*"new_exec": "(([ [:alnum:]_.-]*\/)*)([ [:alnum:]_.-]*)".*/        p_\2 [label="pid \2", shape="diamond"];\
     "f_\5\7" -> "p_\2_\7" [label="exec", color="black"];/p'
echo "}"
} > ${file_name}_data_flow_tmp.dot

awk '!x[$0]++' ${file_name}_data_flow_tmp.dot > ${file_name}_data_flow.dot
rm ${file_name}_data_flow_tmp.dot

# make a png, removing orphaned nodes
gvpr -c 'N[$.degree==0]{delete($G,$);}' ${file_name}_data_flow.dot | dot -Tpng -o ${file_name}_data_flow.dot.png


# separates by pid and executable - display pid as a node

{
echo "digraph $file_name {";
echo "rankdir=\"LR\";"
sed -n -E 's/.*"path": "([ [:alnum:]\\\/_.-]*)".*/"f_\1" [label="\1"];/p' $1 | sort | uniq ;
sed -n -E 's/.*"event": "[[:alnum:]_-]*:[[:alnum:]_-]*:([[:alnum:]_-]*):".*"pid": ([[:digit:]]*).*"exec": "([[:alnum:]_-]*)".*"path": "([ [:alnum:]\\\/_.-]*)".*/    p_\2 [label="pid \2", shape="diamond"];\
    "e_\2_\3" [label="\3", shape="box"];\
     p_\2 -> "e_\2_\3" [dir="none", minlen=2];\
    "e_\2_\3" -> "f_\4" [label="\1"];/p' $1
grep 'new_exec' $1 | sed -n -E 's/.*"event": "[[:alnum:]_-]*:[[:alnum:]_-]*:(.?exec[[:alnum:]_-]*):".*"pid": ([[:digit:]]*).*"uid": ([[:digit:]]*).*"exec": "([[:alnum:]_-]*)".*"new_exec": "([ [:alnum:]_.-]*\/)*([ [:alnum:]_.-]*)".*/    p_\2 [label="pid \2", shape="diamond"];\
    "e_\2_\6" [label="{{\6 | p\2}}", shape="record"];\
    "e_\2_\4" [label="{{\4 | p\2}}", shape="record"];\
    "e_\2_\4" -> "e_\2_\6" [label="exec", color="black"];/p'
grep 'fork' $1 | sed -n -E 's/.*"event": "[[:alnum:]_-]*:[[:alnum:]_-]*:(.?fork[[:alnum:]_-]*):".*"pid": ([[:digit:]]*).*"uid": ([[:digit:]]*).*"exec": "([[:alnum:]_-]*)".*"new_pid": ([[:digit:]]*).*/    p_\2 [label="pid \2", shape="diamond"];\
    "e_\5_\4" [label="{{\4 | p\5}}", shape="record"];\
    "e_\2_\4" [label="{{\4 | p\2}}", shape="record"];\
    "e_\2_\4" -> "e_\5_\4" [label="fork", color=gray15];/p'
echo "}"
} > ${file_name}_full_tmp.dot

awk '!x[$0]++' ${file_name}_full_tmp.dot > ${file_name}_full.dot
rm ${file_name}_full_tmp.dot

# make a png, removing orphaned nodes
gvpr -c 'N[$.degree==0]{delete($G,$);}' ${file_name}_full.dot | dot -Tpng -o ${file_name}_full.dot.png

{
echo "digraph $file_name {";
echo "rankdir=\"LR\";"
echo "\"sample\" [label=\"root user\", shape=\"box\", style=\"filled\", fillcolor=\"0.0 0.4 1.0\"]"
echo "\"sample2\" [label=\"(other users\nvary in color)\", shape=\"box\", style=\"filled\", fillcolor=\"0.1001 0.4 1.0\"]"
echo "\"sample\" -> \"sample2\""
grep 'new_exec' $1 | sed -n -E 's/.*"event": "[[:alnum:]_-]*:[[:alnum:]_-]*:(.?exec[[:alnum:]_-]*):".*"pid": ([[:digit:]]*).*"uid": ([[:digit:]]*).*"exec": "([[:alnum:]_-]*)".*"new_exec": "([ [:alnum:]_.-]*\/)*([ [:alnum:]_.-]*)".*/    p_\2 [label="pid \2", shape="diamond"];\
    "e_\2_\6" [label="{{\6 | p\2}}", shape="record", style="filled", fillcolor="0.\3 0.4 1.0"];\
    "e_\2_\4" [label="{{\4 | p\2}}", shape="record", style="filled", fillcolor="0.\3 0.4 1.0"];\
    "e_\2_\4" -> "e_\2_\6" [label="exec", color="black"];/p'
grep 'fork' $1 | sed -n -E 's/.*"event": "[[:alnum:]_-]*:[[:alnum:]_-]*:(.?fork[[:alnum:]_-]*):".*"pid": ([[:digit:]]*).*"uid": ([[:digit:]]*).*"exec": "([[:alnum:]_-]*)".*"new_pid": ([[:digit:]]*).*/    p_\2 [label="pid \2", shape="diamond"];\
    "e_\5_\4" [label="{{\4 | p\5}}", shape="record", style="filled", fillcolor="0.\3 0.4 1.0"];\
    "e_\2_\4" [label="{{\4 | p\2}}", shape="record", style="filled", fillcolor="0.\3 0.4 1.0"];\
    "e_\2_\4" -> "e_\5_\4" [label="fork", color=gray15];/p'
echo "}"
} > ${file_name}_execs_tmp.dot

awk '!x[$0]++' ${file_name}_execs_tmp.dot > ${file_name}_execs.dot
rm ${file_name}_execs_tmp.dot

# make a png, removing orphaned nodes
gvpr -c 'N[$.degree==0]{delete($G,$);}' ${file_name}_execs.dot | dot -Tpng -o ${file_name}_execs.dot.png
