// #include "evmhost.h"
//
// #include <evmc/evmc.hpp>
//
// class Host : public evmc::Host {
//
// };
//
// extern "C" {
//
//   const evmc_host_interface* host_get_interface()
//   {
//     return &evmc::Host::get_interface();
//   }
//
//   //evmc_host_context* host_create_context(evmc_tx_context tx_context)
//   //{
//   //  auto host = new Host;
//   //  return host->to_context();
//   //}
//
//   void host_destroy_context(evmc_host_context* context)
//   {
//     delete evmc::Host::from_context<ExampleHost>(context);
//   }
// }