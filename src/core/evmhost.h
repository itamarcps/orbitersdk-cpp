#ifndef EVMHOST_H
#define EVMHOST_H


// EVMC: Ethereum Client-VM Connector API.
// Copyright 2016 The EVMC Authors.
// Licensed under the Apache License, Version 2.0.

#include <evmc/evmc.h>


namespace EVM {
#if __cplusplus
  extern "C" {
#endif

    const struct evmc_host_interface* host_get_interface(void);

    struct evmc_host_context* host_create_context(struct evmc_tx_context tx_context);

    void host_destroy_context(struct evmc_host_context* context);

#if __cplusplus
  }
#endif
}

#endif // EVMHOST_H