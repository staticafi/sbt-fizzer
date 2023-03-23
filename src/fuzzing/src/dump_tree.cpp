#include <fuzzing/dump_tree.hpp>
#include <fuzzing/branching_node.hpp>
#include <utility/invariants.hpp>
#include <iostream>
#include <sstream>

namespace  fuzzing {


static char label_to_char(branching_node::successor_pointer::LABEL const  label)
{
    switch (label)
    {
    case branching_node::successor_pointer::NOT_VISITED: return '?';
    case branching_node::successor_pointer::END_EXCEPTIONAL: return '!';
    case branching_node::successor_pointer::END_NORMAL: return 'X';
    case branching_node::successor_pointer::VISITED: return '>';
    default: UNREACHABLE(); break;
    }
}


void  dump_subtree_raw(
        branching_node const*  node,
        std::string const&  seek,
        char const  label_char,
        tree_dump_info const&  info
        )
{
    info.ostr << seek << label_char;
    if (node != nullptr)
        info.ostr << node->id;
    info.ostr << '\n';
    info.ostr.flush();
    if (node != nullptr)
    {
        dump_subtree_raw(node->successors.front().pointer, seek + info.tab, label_to_char(node->successors.front().label), info);
        dump_subtree_raw(node->successors.back().pointer, seek + info.tab, label_to_char(node->successors.back().label), info);
    }
}

static void  dump_subtree_dot(
        std::string const&  pred_id,
        branching_node const* const  node,
        int& null_idx,
        char const label,
        bool const direction,
        std::ostream&  ostr)
{
    std::string  id;
    if (node != nullptr)
    {
        std::stringstream  sstr;
        sstr << '"' << (void*)node << '"';
        id = sstr.str();
    }
    else
    {
        std::stringstream  sstr;
        sstr << '"' << -(++null_idx) << '"';
        id = sstr.str();
    }

    std::string  name;
    if (node != nullptr)
    {
        std::stringstream  sstr;
        sstr << '"' << node->id;
        if (node->sensitivity_performed && !node->sensitive_stdin_bits.empty())
            sstr << " | " << node->sensitive_stdin_bits.size();
        sstr << '"';
        name = sstr.str();
    }
    else
    {
        std::stringstream  sstr;
        sstr << '"' << label << '"';
        name = sstr.str();
    }

    ostr << "    " << id << " [label=" << name;
    if (node != nullptr)
    {
        if (node->sensitivity_performed && node->sensitive_stdin_bits.empty())
            ostr << ", shape=oval";
        if (node->minimization_performed && node->jetklee_queued)
        {
            INVARIANT(node->sensitivity_performed);
            ostr << ", style=filled, fillcolor=gold";
        }
        else if (node->minimization_performed)
        {
            INVARIANT(node->sensitivity_performed);
            ostr << ", style=filled, fillcolor=orange";
        }
        else if (node->jetklee_queued)
        {
            INVARIANT(node->sensitivity_performed);
            ostr << ", style=filled, fillcolor=magenta";
        }
        else if (node->sensitivity_performed)
            ostr << ", style=filled, fillcolor=gray";
    }
    else
        ostr << ", shape=plaintext";
    ostr << "]\n";
    if (!pred_id.empty())
        ostr << "    " << pred_id << " -> " << id << " [color=\"" << (direction ? "green" : "red") << "\"]" << '\n';

    if (node != nullptr)
    {
        dump_subtree_dot(id, node->successors.front().pointer, null_idx, label_to_char(node->successors.front().label), false, ostr);
        dump_subtree_dot(id, node->successors.back().pointer, null_idx, label_to_char(node->successors.back().label), true, ostr);
    }
}

void  dump_subtree_dot(branching_node const* const  start_node, std::ostream&  ostr)
{
    ostr << "digraph G {\n"
         << "    node [shape=\"box\"]\n";

    int null_idx = 0;
    dump_subtree_dot("", start_node, null_idx, ' ', false, ostr);

    ostr << "}\n";
    ostr.flush();
}


}
