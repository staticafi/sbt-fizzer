#include <connection/server.hpp>
#include <connection/client.hpp>
#include <connection/medium.hpp>
#include <iomodels/iomanager.hpp>
#include <sstream>

namespace  connection {


server&  server::instance()
{
    static server  s;
    return s;
}


void  server::execute_program_on_client()
{
    medium::instance().clear();
    iomodels::iomanager::instance().save_stdin(medium::instance());
    iomodels::iomanager::instance().save_stdout(medium::instance());

    client::instance().execute_program_and_send_results();

    iomodels::iomanager::instance().clear_trace();
    iomodels::iomanager::instance().load_trace(medium::instance());
    iomodels::iomanager::instance().clear_stdin();
    iomodels::iomanager::instance().load_stdin(medium::instance());
    iomodels::iomanager::instance().clear_stdout();
    iomodels::iomanager::instance().load_stdout(medium::instance());
}


}
