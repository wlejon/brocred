#include "check.h"
#include "brocred/event_queue.h"
#include "brocred/events.h"

#include <atomic>
#include <thread>
#include <vector>

using namespace brocred;

static void test_order_and_drain() {
    MessageQueue<int> q;
    for (int i = 0; i < 5; ++i) {
        q.push(i);
    }
    CHECK_EQ(q.size(), size_t(5));
    CHECK(!q.empty());

    auto drained = q.drain();
    CHECK_EQ(drained.size(), size_t(5));
    for (int i = 0; i < 5; ++i) {
        CHECK_EQ(drained[i], i);
    }
    CHECK(q.empty());
    CHECK_EQ(q.size(), size_t(0));
}

static void test_multi_producer() {
    MessageQueue<int> q;
    std::atomic<int> wakes{0};
    q.set_wake([&] { wakes.fetch_add(1); });

    std::vector<std::thread> producers;
    constexpr int kThreads = 4;
    constexpr int kItemsPerThread = 500;

    for (int t = 0; t < kThreads; ++t) {
        producers.emplace_back([&q, t] {
            for (int i = 0; i < kItemsPerThread; ++i) {
                q.push(t * 10000 + i);
            }
        });
    }

    for (auto& p : producers) {
        p.join();
    }

    CHECK_EQ(wakes.load(), kThreads * kItemsPerThread);
    auto drained = q.drain();
    CHECK_EQ(drained.size(), size_t(kThreads * kItemsPerThread));

    int last[kThreads] = {-1, -1, -1, -1};
    for (int val : drained) {
        int t = val / 10000;
        int i = val % 10000;
        CHECK(i > last[t]);
        last[t] = i;
    }
}

static void test_wait_for() {
    MessageQueue<std::string> q;
    CHECK(!q.wait_for(std::chrono::milliseconds(20)));

    std::thread producer([&] {
        std::this_thread::sleep_for(std::chrono::milliseconds(30));
        q.push("wakeup_item");
    });

    CHECK(q.wait_for(std::chrono::milliseconds(2000)));
    producer.join();

    auto v = q.drain();
    REQUIRE(v.size() == 1);
    CHECK_EQ(v[0], std::string("wakeup_item"));
}

int main() {
    test_order_and_drain();
    test_multi_producer();
    test_wait_for();
    return bstest::finish("test_event_queue");
}
