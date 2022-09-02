#include <connection/client_main.hpp>
#include <iomodels/iomanager.hpp>
#include <iomodels/stdin_replay_bits_then_repeat_85.hpp>
#include <iomodels/stdout_void.hpp>
#include <utility/assumptions.hpp>

namespace  connection {


void  client_main()
{
    iomodels::iomanager::instance().set_stdin(std::make_shared<iomodels::stdin_replay_bits_then_repeat_85>());
    iomodels::iomanager::instance().set_stdout(std::make_shared<iomodels::stdout_void>());

}


}
