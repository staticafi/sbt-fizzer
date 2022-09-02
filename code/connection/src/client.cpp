#include <connection/client.hpp>
#include <connection/medium.hpp>
#include <iomodels/iomanager.hpp>


namespace  connection {


client&  client::instance()
{
    static client  s;
    return s;
}


void  client::execute_program_and_send_results()
{
    iomodels::iomanager::instance().clear_trace();
    iomodels::iomanager::instance().clear_stdin();
    iomodels::iomanager::instance().load_stdin(medium::instance());
    iomodels::iomanager::instance().clear_stdout();
    iomodels::iomanager::instance().load_stdout(medium::instance());

    medium::instance().clear();
    iomodels::iomanager::instance().save_trace(medium::instance());
    iomodels::iomanager::instance().save_stdin(medium::instance());
    iomodels::iomanager::instance().save_stdout(medium::instance());
}


}
