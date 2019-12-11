#pragma once

#include <memory>

/// quota_tracker uses a std::deque to store time-ordered information about
/// events.  It can count events within a pre-set, fixed time threshold, to
/// decide if a new event can be allowed without violating a quota.
class quota_tracker {
  /// Internal is the class that stores all the members of a quota_tracker
  /// object. To avoid pulling too much into the .h file, we are using the PIMPL
  /// pattern (https://www.geeksforgeeks.org/pimpl-idiom-in-c-with-examples/)
  struct Internal;

  /// A reference to the internal fields of the quota_tracker object
  std::unique_ptr<Internal> fields;

public:
  /// Construct a circular buffer that limits usage to quota_amount per
  /// quota_duration seconds
  ///
  /// @param amount   The maximum amount of service
  /// @param duration The time during the service maximum can be spread out
  quota_tracker(size_t amount, double duration);

  /// Construct a quota_tracker from another quota_tracker
  ///
  /// @param other The quota tracker to use to build a new quota tracker
  quota_tracker(const quota_tracker &other);

  /// Destruct a quota tracker
  ~quota_tracker();

  /// Decides if a new event is permitted.  The attempt is allowed if it could
  /// be added to events, while ensuring that the sum of amounts for all events
  /// with (time > now-q_dur), is less than q_amnt.
  ///
  /// @param amount The amount of the new request
  ///
  /// @returns True if the amount could be added without violating the quota
  bool check(size_t amount);

  /// Actually add a new event to the quota tracker
  void add(size_t amount);
};