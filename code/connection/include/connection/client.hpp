#ifndef CONNECTION_CLIENT_HPP_INCLUDED
#   define CONNECTION_CLIENT_HPP_INCLUDED

namespace  connection {


struct  client
{
    static client&  instance();

    void  execute_program_and_send_results();

private:
    client() = default;
};


}

#endif
