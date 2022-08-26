#ifndef CONNECTION_SERVER_HPP_INCLUDED
#   define CONNECTION_SERVER_HPP_INCLUDED

namespace  connection {


struct  server
{
    static server&  instance();

    void  execute_program_on_client();

private:
    server() = default;
};


}

#endif
