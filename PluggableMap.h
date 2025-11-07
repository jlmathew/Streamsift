/**
 * @file PluggableMap.h
 * @brief Provides swappable map type definitions using 'using' aliases.
 *
 * This allows the underlying map implementation (e.g., std::unordered_map,
 * std::map, or a third-party library) to be changed by defining a
 * preprocessor macro (e.g., USE_STD_MAP).
 */

#ifndef __PLUGGABLE_MAP_H__
#define __PLUGGABLE_MAP_H__

#include <map>
#include <unordered_map>
#include <functional> // for std::hash, std::equal_to

/*
* To use a different map, add a new #elif block and define
* PluggableUnorderedMap and PluggableOrderedMap.
*
* Example:
* #elif defined(USE_ABSEIL_MAP)
* #include <absl/container/flat_hash_map.h>
* template<typename K, typename V, typename H = std::hash<K>, typename E = std::equal_to<K>>
* using PluggableUnorderedMap = absl::flat_hash_map<K, V, H, E>;
*/

#if defined(USE_STD_MAP)
    /**
     * @brief An ordered map (std::map) for debugging or when order is required.
     */
    template<typename K, typename V, typename H = std::hash<K>, typename E = std::equal_to<K>>
    using PluggableUnorderedMap = std::map<K, V>; // Note: Ignores H and E

    /**
     * @brief A standard ordered map (std::map).
     */
    template<typename K, typename V, typename C = std::less<K>>
    using PluggableOrderedMap = std::map<K, V, C>;

#else
    /**
     * @brief Default high-performance hash map (std::unordered_map).
     */
    template<typename K, typename V, typename H = std::hash<K>, typename E = std::equal_to<K>>
    using PluggableUnorderedMap = std::unordered_map<K, V, H, E>;

    /**
     * @brief A standard ordered map (std::map).
     */
    template<typename K, typename V, typename C = std::less<K>>
    using PluggableOrderedMap = std::map<K, V, C>;
#endif

#endif // __PLUGGABLE_MAP_H__