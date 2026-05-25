// adapted from test262 test/built-ins/Promise/prototype/{then,catch,finally}/ (BSD-licensed)
// Sync-path .then/.catch/.finally chain. Hermes executes microtasks
// deterministically in the same tick; output order reflects chain resolution.

Promise.resolve(1)
    .then(function(v) { print("then1:" + v); return v + 1; })
    .then(function(v) { print("then2:" + v); return v + 1; })
    .catch(function(e) { print("catch:" + e); })
    .finally(function() { print("finally"); });

Promise.reject("boom")
    .then(function(v) { print("skip:" + v); })
    .catch(function(e) { print("caught:" + e); })
    .finally(function() { print("done"); });
