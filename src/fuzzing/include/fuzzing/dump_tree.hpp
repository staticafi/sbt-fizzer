#ifndef FUZZING_DUMP_TREE_HPP_INCLUDED
#   define FUZZING_DUMP_TREE_HPP_INCLUDED

#   include <string>
#   include <iostream>

namespace  fuzzing {


struct  branching_node;


struct  tree_dump_info
{
    std::ostream&  ostr { std::cout };
    std::string  tab{ " " };
};

void  dump_subtree_raw(
        branching_node const*  node,
        std::string const&  seek = "",
        char const  label_char = ' ',
        tree_dump_info const&  info = {}
        );

// To see the dumped the graph you can install the extension "Graphviz Interactive Preview" by "tintinweb"
// to VSCode, save the graph to '.dot' file, which then can be previewed by the extension.
// Alternatively, you can go to page: https://dreampuf.github.io/GraphvizOnline
// and copy-paste the graph to the left panel to see the plot in the right panel.
void  dump_subtree_dot(branching_node const* const  start_node, std::ostream&  ostr = std::cout);


}

#endif
