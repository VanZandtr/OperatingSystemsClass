// http://www.cplusplus.com/reference/ctime/time/ is helpful here
#include <deque>
#include <time.h>
#include <iostream>
#include "quota_tracker.h"
#include <list>

using namespace std;


/// quota_tracker::Internal is the class that stores all the members of a
/// quota_tracker object. To avoid pulling too much into the .h file, we are
/// using the PIMPL pattern
/// (https://www.geeksforgeeks.org/pimpl-idiom-in-c-with-examples/

struct quota_tracker::Internal {
  /// An event is a timestamped amount.  We don't care what the amount
  /// represents, because the code below will only sum the amounts in a
  /// collection of events and compare it against a quota.
  struct event {
    /// The time at which the request was made
    time_t when;

    /// The amount of resource consumed at the above time
    size_t amnt;
  };

  //variables
  size_t amount;
  double duration;
  //std::deque <const event *> events;
  std::list <const event> events;

  /// Construct the Internal object
  ///
  /// @param amount   The maximum amount of service
  /// @param duration The time during the service maximum can be spread out
  Internal(size_t amount, double duration) : amount(amount), duration(duration) {}
};

/// Construct an object that limits usage to quota_amount per quota_duration
/// seconds
///
/// @param amount   The maximum amount of service
/// @param duration The time during the service maximum can be spread out
quota_tracker::quota_tracker(size_t amount, double duration): fields(new Internal(amount, duration)) {}

/// Construct a quota_tracker from another quota_tracker
///
/// @param other The quota tracker to use to build a new quota tracker
quota_tracker::quota_tracker(const quota_tracker &other) : fields(new Internal(other.fields->amount, other.fields->duration)) {
  /*
  for(size_t i = 0; i < other.fields->events.size(); i++){
    fields->events.push_back(other.fields->events[i]);
  }
  */
  for (std::list<const Internal::event>::const_iterator iterator = other.fields->events.begin(), end = other.fields->events.end(); iterator != end; ++iterator) {
    fields->events.push_back(*iterator);
  }
}

/// Destruct a quota tracker
quota_tracker::~quota_tracker() = default;

/// Decides if a new event is permitted.  The attempt is allowed if it could
/// be added to events, while ensuring that the sum of amounts for all events
/// with (time > now-q_dur), is less than q_amnt.
///
/// @param amount The amount of the new request
///
/// @returns True if the amount could be added without violating the quota
bool quota_tracker::check(size_t amount) {

  double total_amounts = 0.0;
  //size_t i = 0;
  time_t time_now = time(nullptr);
  
  //check if events is 0
  if(fields->events.size() == 0){
    return true;
  }
  //check for old times
  
  /*
  while((time_now - fields->events[i]->when) > fields->duration){
    //remove old events
    fields->events.pop_front();
    i++;
    //cout << "(In the while loop, after remove old events) | "  "Events size is: " << fields->events.size();
  }
  */
  /*
  for (std::list<const Internal::event>::const_iterator iterator = fields->events.begin(), end = fields->events.end(); iterator != end; ++iterator) {
    //cout << "iterator->when"<< iterator->when << endl;
    //cout << "(time_now - iterator->when)"<< (time_now - iterator->when) << endl;
    //cout << "fields->duration"<< fields->duration << endl;
    
    if((time_now - iterator->when) > fields->duration){
      //cout << "POPPING" << endl;
      //fields->events.pop_front();
    }
  }
  */
  //cout << "TESTING front.when: " << ((fields->events.front()).when) << endl;
  while(true) {
    if((fields->events.size()) == 0){
      break;
    }

    if((time_now - (fields->events.front()).when) < fields->duration){
      break;
    }
    
    //cout << "front before: "<< (fields->events.size())<< endl;
    fields->events.pop_front();
    //cout << "front after: "<< (fields->events.size())<< endl;
  }

  //get total time
  /*
  for(i = 0; i < fields->events.size(); i++)
  {
    //cout << "Events size is: " << fields->events.size();
    //cout << "events[" << i << "]" << fields->events[i]->amnt << endl;
    total_amounts = total_amounts + fields->events[i]->amnt;
  }
  */

  for (std::list<const Internal::event>::const_iterator iterator = fields->events.begin(), end = fields->events.end(); iterator != end; ++iterator) {
    //cout << "total amounts1: "<< total_amounts << endl;
    total_amounts = total_amounts + (iterator->amnt);
  }
  ////cout << "(After get total time) | " << "Events size is: " << fields->events.size();

  //check if we can add the event
  //cout << "total amounts + amount: "<< total_amounts + amount << endl;
  //cout << "fields->amount < ta + a?: "<< ((total_amounts + amount) > fields->amount) << endl;
  //cout << "" << endl;
  if((total_amounts + amount) > fields->amount){
    //cout << "fields->amount: "<< fields->amount<< endl;
    return false;
  }

  return true; 
}

/// Actually add a new event to the quota tracker
void quota_tracker::add(size_t amount) {
  time_t time_now = time(nullptr);

  Internal::event new_event;
  new_event.amnt = amount;
  new_event.when = time_now;

  //fields->events.push_back(&new_event);
  fields->events.push_back(new_event);
  
}

void quota_tracker::operator=(const quota_tracker& other){
  fields->amount = other.fields->amount;
  fields->duration = other.fields->duration;
  
  /*
  for(size_t i = 0; i < other.fields->events.size(); i++){
    fields->events.push_back(other.fields->events[i]);
  }
  */

  for (std::list<const Internal::event>::const_iterator iterator = other.fields->events.begin(), end = other.fields->events.end(); iterator != end; ++iterator) {
    fields->events.push_back(*iterator);
  }
}