#include <atomic>
#include <condition_variable>
#include <functional>
#include <mutex>
#include <queue>
#include <thread>
#include <unistd.h>
#include <vector>
#include "pool.h"
#include <iostream>

using namespace std;

//https://codereview.stackexchange.com/questions/166406/thread-pool-implementation

/// thread_pool::Internal is the class that stores all the members of a
/// thread_pool object. To avoid pulling too much into the .h file, we are using
/// the PIMPL pattern
/// (https://www.geeksforgeeks.org/pimpl-idiom-in-c-with-examples/)
struct thread_pool::Internal
{
  /// construct the Internal object by setting the fields that are
  /// user-specified
  ///
  std::queue<int> _work_queue;
  bool _running;
  std::condition_variable cv;
  std::mutex _mutex;
  std::vector<std::thread> _threads;
  function<void()> shut_down;
  function<bool(int)> serveClientHandler;

  /// @param handler The code to run whenever something arrives in the pool, need to have it like this
  Internal(function<bool(int)> handler):_running(true) {
    serveClientHandler = handler;
  }
};
/// construct a thread pool by providing a size and the function to run on
/// each element that arrives in the queue
///
/// @param size    The number of threads in the pool
/// @param handler The code to run whenever something arrives in the pool
thread_pool::thread_pool(int size, function<bool(int)> handler) : fields(new Internal(handler))
{

  auto thread_loop = [&](size_t id) {
    //set a lock
    std::unique_lock<std::mutex> lock(fields->_mutex);

    do{
        //cv.wait(lk, [&]{ return check_func(i,k); });
        if(!fields->_work_queue.size() || fields->_running){
          fields->cv.wait(lock);
        }

        if(fields->_running && fields->_work_queue.size()){
          //get next job
          auto work = fields->_work_queue.front();

          //pop from queue
          fields->_work_queue.pop();

          //check true call shutdown handler;
          if (fields->serveClientHandler(work) == true)
          {
            //got BYE
            fields->shut_down();
          }

          //close sd
          close(work);
        }
    }while(fields->_running);
  };

  fields->_threads.reserve(size);
  unsigned int unsigned_size = (unsigned int) size;
  for (size_t i = 0; i < unsigned_size; i++)
  {
    fields->_threads.push_back(std::thread(thread_loop, i));
  }
}

/// destruct a thread pool
thread_pool::~thread_pool() = default;

/// Allow a user of the pool to provide some code to run when the pool decides
/// it needs to shut down.
///
/// @param func The code that should be run when the pool shuts down
void thread_pool::set_shutdown_handler(function<void()> func)
{
  fields->shut_down = func;
}

/// Allow a user of the pool to see if the pool has been shut down
bool thread_pool::check_active()
{
  if (fields->_running == false)
  {
    return false;
  }
  return true;
}

/// Shutting down the pool can take some time.  await_shutdown() lets a user
/// of the pool wait until the threads are all done servicing clients.
void thread_pool::await_shutdown()
{
  fields->_mutex.lock();

  fields->_running = false;
  //wake up all threads
  fields->cv.notify_all();

  fields->_mutex.unlock();

  //join the threads
  for (size_t i = 0; i < fields->_threads.size(); i++)
  {
    fields->_threads[i].join();
  }
}

/// When a new connection arrives at the server, it calls this to pass the
/// connection to the pool for processing.
///
/// @param sd The socket descriptor for the new connection
void thread_pool::service_connection(int sd)
{
  std::lock_guard<std::mutex> lock(fields->_mutex);
  fields->_work_queue.push(sd);
  fields->cv.notify_one();
}
