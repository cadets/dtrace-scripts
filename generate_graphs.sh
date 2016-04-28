#!/bin/sh

# 1st arguement is a CADETS trace file - will create a png 
# requires graphviz to be installed

file_name=$(basename -s'.json' $1)

{
echo "strict digraph $file_name {"; 
echo "rankdir=\"LR\";"
sed -n -E 's/.*"path": "([ [:alnum:]\\\/_.-]*)".*/"f_\1" [label="\1"];/p' $1 | sort | uniq ; 
grep 'write' $1 | sed -n -E 's/.*"event": "[[:alnum:]_-]*:[[:alnum:]_-]*:(.?write[[:alnum:]_-]*):".*"pid": ([[:digit:]]*).*"exec": "([[:alnum:]_-]*)".*"path": "([ [:alnum:]\\\/_.-]*)".*/    p_\2 [label="pid \2", shape="diamond"];\
    "p_\2_\3" [label="\3\
p\2", shape="box"];\
    "p_\2_\3" -> "f_\4" [label="write", color="saddlebrown"];/p'
grep 'read' $1 | sed -n -E 's/.*"event": "[[:alnum:]_-]*:[[:alnum:]_-]*:(.?read[[:alnum:]_-]*):".*"pid": ([[:digit:]]*).*"exec": "([[:alnum:]_-]*)".*"path": "([ [:alnum:]\\\/_.-]*)".*/    p_\2 [label="pid \2", shape="diamond"];\
    "p_\2_\3" [label="\3\
p\2", shape="box"];\
    "f_\4" -> "p_\2_\3" [label="read", color="black"];/p'
grep 'mmap' $1 | sed -n -E 's/.*"event": "[[:alnum:]_-]*:[[:alnum:]_-]*:(.?mmap[[:alnum:]_-]*):".*"pid": ([[:digit:]]*).*"exec": "([[:alnum:]_-]*)".*"path": "([ [:alnum:]\\\/_.-]*)".*/    p_\2 [label="pid \2", shape="diamond"];\
    "p_\2_\3" [label="\3\
p\2", shape="box"];\
    "f_\4" -> "p_\2_\3" [label="mmap", color="black"];/p'
echo "}" 
} > ${file_name}_data_flow.dot

# make a png, removing orphaned nodes
gvpr -c 'N[$.degree==0]{delete($G,$);}' ${file_name}_data_flow.dot | dot -Tpng -o ${file_name}_data_flow.dot.png


# separates by pid and executable - display pid as a node

{
echo "strict digraph $file_name {"; 
echo "rankdir=\"LR\";"
sed -n -E 's/.*"path": "([ [:alnum:]\\\/_.-]*)".*/"f_\1" [label="\1"];/p' $1 | sort | uniq ; 
sed -n -E 's/.*"event": "[[:alnum:]_-]*:[[:alnum:]_-]*:([[:alnum:]_-]*):".*"pid": ([[:digit:]]*).*"exec": "([[:alnum:]_-]*)".*"path": "([ [:alnum:]\\\/_.-]*)".*/    p_\2 [label="pid \2", shape="diamond"];\
    "p_\2_\3" [label="\3", shape="box"];\
     p_\2 -> "p_\2_\3" [dir="none", minlen=2];\
    "p_\2_\3" -> "f_\4" [label="\1"];/p' $1 
echo "}" 
} > ${file_name}_full.dot

# make a png, removing orphaned nodes
gvpr -c 'N[$.degree==0]{delete($G,$);}' ${file_name}_full.dot | dot -Tpng -o ${file_name}_full.dot.png

