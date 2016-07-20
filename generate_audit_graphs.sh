#!/bin/sh

# 1st arguement is a CADETS trace file - will create a svg
# requires graphviz to be installed

file_name=$(basename -s'.json' $1)

#TODO process id is saved in subjuuid - more unique?
{
echo "digraph $file_name {";
echo "rankdir=\"LR\";"
grep 'open' $1 | sed -n -E 's/.*"event": "[[:alnum:]_-]*:[[:alnum:]_-]*:.{0,5}open[[:alnum:]_-]*:".*"pid": [[:digit:]]*.*"exec": "[[:alnum:]_-]*".*"arg_objuuid1": "([ [:alnum:]\\\/_.-]*)".*"upath1": "([ [:alnum:]\\\/_.-]*)".*/    "\1" [label="\2"];/p'
sed -n -E 's/.*"upath1": "([ [:alnum:]\\\/_.-]*)".*/"f_\1" [label="\1"];/p' $1 | sort | uniq ;
grep 'write' $1 | sed -n -E 's/.*"event": "[[:alnum:]_-]*:[[:alnum:]_-]*:(.{0,5}write[[:alnum:]_-]*):".*"pid": ([[:digit:]]*).*"exec": "([[:alnum:]_-]*)".*"arg_objuuid1": "([ [:alnum:]\\\/_.-]*)".*/    p_\2 [label="pid \2", shape="diamond"];\
    "p_\2_\3" [label="{{\3 | p\2}}", shape="record"];\
    "p_\2_\3" -> "\4" [label="write", color="saddlebrown"];/p'
grep 'read' $1 | sed -n -E 's/.*"event": "[[:alnum:]_-]*:[[:alnum:]_-]*:(.{0,5}read[[:alnum:]_-]*):".*"pid": ([[:digit:]]*).*"exec": "([[:alnum:]_-]*)".*"arg_objuuid1": "([ [:alnum:]\\\/_.-]*)".*/    p_\2 [label="pid \2", shape="diamond"];\
    "p_\2_\3" [label="{{\3 | p\2}}", shape="record"];\
    "\4" -> "p_\2_\3" [label="read", color="black"];/p'
grep 'mmap' $1 | sed -n -E 's/.*"event": "[[:alnum:]_-]*:[[:alnum:]_-]*:(.{0,5}mmap[[:alnum:]_-]*):".*"pid": ([[:digit:]]*).*"exec": "([[:alnum:]_-]*)".*"arg_objuuid1": "([ [:alnum:]\\\/_.-]*)".*/    p_\2 [label="pid \2", shape="diamond"];\
    "p_\2_\3" [label="{{\3 | p\2}}", shape="record"];\
    "\4" -> "p_\2_\3" [label="mmap", color="black"];/p'
grep 'upath1' $1 | sed -n -E 's/.*"event": "[[:alnum:]_-]*:[[:alnum:]_-]*:(.{0,5}exec[[:alnum:]_-]*):".*"pid": ([[:digit:]]*).*"uid": ([[:digit:]]*).*"exec": "([[:alnum:]_-]*)".*"upath1": "(([ [:alnum:]_.-]*\/)*)([ [:alnum:]_.-]*)".*/        p_\2 [label="pid \2", shape="diamond"];\
     "\5\7" -> "p_\2_\7" [label="exec", color="black"];/p'
echo "}"
} > ${file_name}_data_flow_tmp.dot

awk '!x[$0]++' ${file_name}_data_flow_tmp.dot > ${file_name}_data_flow.dot
rm ${file_name}_data_flow_tmp.dot

# make a svg, removing orphaned nodes
gvpr -c 'N[$.degree==0]{delete($G,$);}' ${file_name}_data_flow.dot | dot -Tsvg -o ${file_name}_data_flow.dot.svg


# separates by pid and executable - display pid as a node
#TODO process id is saved in subjuuid - more unique?

{
echo "digraph $file_name {";
echo "rankdir=\"LR\";"
sed -n -E 's/.*"upath1": "([ [:alnum:]\\\/_.-]*)".*/"f_\1" [label="\1"];/p' $1 | sort | uniq ;
sed -n -E 's/.*"event": "[[:alnum:]_-]*:[[:alnum:]_-]*:([[:alnum:]_-]*):".*"pid": ([[:digit:]]*).*"exec": "([[:alnum:]_-]*)".*"upath1": "([ [:alnum:]\\\/_.-]*)".*/    p_\2 [label="pid \2", shape="diamond"];\
    "e_\2_\3" [label="\3", shape="box"];\
     p_\2 -> "e_\2_\3" [dir="none", minlen=2];\
    "e_\2_\3" -> "f_\4" [label="\1"];/p' $1
grep 'upath1' $1 | sed -n -E 's/.*"event": "[[:alnum:]_-]*:[[:alnum:]_-]*:(.{0,5}exec[[:alnum:]_-]*):".*"pid": ([[:digit:]]*).*"uid": ([[:digit:]]*).*"exec": "([[:alnum:]_-]*)".*"upath1": "([ [:alnum:]_.-]*\/)*([ [:alnum:]_.-]*)".*/    p_\2 [label="pid \2", shape="diamond"];\
    "e_\2_\6" [label="{{\6 | p\2}}", shape="record"];\
    "e_\2_\4" [label="{{\4 | p\2}}", shape="record"];\
    "e_\2_\4" -> "e_\2_\6" [label="exec", color="black"];/p'
grep 'fork' $1 | sed -n -E 's/.*"event": "[[:alnum:]_-]*:[[:alnum:]_-]*:(.{0,5}fork[[:alnum:]_-]*):".*"pid": ([[:digit:]]*).*"uid": ([[:digit:]]*).*"exec": "([[:alnum:]_-]*)".*"retval": ([[:digit:]]*).*/    p_\2 [label="pid \2", shape="diamond"];\
    "e_\5_\4" [label="{{\4 | p\5}}", shape="record"];\
    "e_\2_\4" [label="{{\4 | p\2}}", shape="record"];\
    "e_\2_\4" -> "e_\5_\4" [label="fork", color=gray15];/p'
echo "}"
} > ${file_name}_full_tmp.dot

awk '!x[$0]++' ${file_name}_full_tmp.dot > ${file_name}_full.dot
rm ${file_name}_full_tmp.dot

# make a svg, removing orphaned nodes
gvpr -c 'N[$.degree==0]{delete($G,$);}' ${file_name}_full.dot | dot -Tsvg -o ${file_name}_full.dot.svg

#TODO process id is saved in subjuuid - more unique?
{
echo "digraph $file_name {";
echo "rankdir=\"LR\";"
echo "\"sample\" [label=\"root user\", shape=\"box\", style=\"filled\", fillcolor=\"0.0 0.4 1.0\"]"
echo "\"sample2\" [label=\"(other users\nvary in color)\", shape=\"box\", style=\"filled\", fillcolor=\"0.1001 0.4 1.0\"]"
echo "\"sample\" -> \"sample2\""
grep 'upath1' $1 | sed -n -E 's/.*"event": "[[:alnum:]_-]*:[[:alnum:]_-]*:(.{0,5}exec[[:alnum:]_-]*):".*"pid": ([[:digit:]]*).*"uid": ([[:digit:]]*).*"exec": "([[:alnum:]_-]*)".*"upath1": "([ [:alnum:]_.-]*\/)*([ [:alnum:]_.-]*)".*/    p_\2 [label="pid \2", shape="diamond"];\
    "e_\2_\6" [label="{{\6 | p\2}}", shape="record", style="filled", fillcolor="0.\3 0.4 1.0"];\
    "e_\2_\4" [label="{{\4 | p\2}}", shape="record", style="filled", fillcolor="0.\3 0.4 1.0"];\
    "e_\2_\4" -> "e_\2_\6" [label="exec", color="black"];/p'
grep 'fork' $1 | sed -n -E 's/.*"event": "[[:alnum:]_-]*:[[:alnum:]_-]*:(.{0,5}fork[[:alnum:]_-]*):".*"pid": ([[:digit:]]*).*"uid": ([[:digit:]]*).*"exec": "([[:alnum:]_-]*)".*"retval": ([[:digit:]]*).*/    p_\2 [label="pid \2", shape="diamond"];\
    "e_\5_\4" [label="{{\4 | p\5}}", shape="record", style="filled", fillcolor="0.\3 0.4 1.0"];\
    "e_\2_\4" [label="{{\4 | p\2}}", shape="record", style="filled", fillcolor="0.\3 0.4 1.0"];\
    "e_\2_\4" -> "e_\5_\4" [label="fork", color=gray15];/p'
echo "}"
} > ${file_name}_execs_tmp.dot

awk '!x[$0]++' ${file_name}_execs_tmp.dot > ${file_name}_execs.dot
rm ${file_name}_execs_tmp.dot

# make a svg, removing orphaned nodes
gvpr -c 'N[$.degree==0]{delete($G,$);}' ${file_name}_execs.dot | dot -Tsvg -o ${file_name}_execs.dot.svg
