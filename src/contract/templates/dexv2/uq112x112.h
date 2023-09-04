#ifndef UQ112X112_H
#define UQ112X112_H

#include "../../../utils/utils.h"

/// Namespace for dealing with fixed point fractions in DEX contracts.
namespace UQ112x112 {
  /// Constant for performing the UQ112x112 calculations.
  static const uint256_t Q112("5192296858534827628530496329220096");

  /**
   * Encode a uint112 as a UQ112x112.
   * @param x The uint to encode.
   * @return The encoded uint.
   */
  static uint256_t encode(const uint256_t& x) { return (x * Q112); }

  /**
   * Divide a UQ112x112 by a uint112.
   * @param x The dividend uint.
   * @param y The divisor uint.
   * @return The quotient uint.
   */
  static uint256_t uqdiv(const uint256_t& x, const uint256_t& y) { return (x / y); }
};

#endif // UQ112X112_H
