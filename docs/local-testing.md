# Local testing

Use the fast contract gate for no-emulator feedback on evidence, workflow, privacy, and delivery contracts:

```sh
GENEWHIP_PROCESS_CONTEXT=host-cleanup-v1 bash scripts/ci/required-gate.sh --phase7-fast
```

The `host-cleanup-v1` value selects the existing process-cleanup contract context. The fast gate runs contracts and bounded synthetic child-process fixtures; it does not run emulator or title workloads or establish compatibility. The repository's hosted CI workflow runs on its declared PR, push, merge-group, schedule, and manual events.

To run an individual changed contract:

```sh
python3 -I tests/evidence/phase7_fresh_batch_contract.py
python3 -I tests/evidence/ci_timing_contract.py
GENEWHIP_PROCESS_CONTEXT=host-cleanup-v1 python3 -I tests/evidence/v02_qualification_contract.py --contracts
python3 -I tests/evidence/public_hygiene.py
```

For focused SDL-free core feedback, configure with CMake 3.27+, Ninja, a C17 compiler, and Python 3. This path builds and runs only four bounded unit contracts:

```sh
cmake -S . -B build/local-core -G Ninja -DCMAKE_BUILD_TYPE=Release \
  -DBUILD_TESTING=ON -DGENEWHIP_BUILD_TOOLS=OFF -DGENEWHIP_BUILD_DESKTOP=OFF \
  -DGENEWHIP_TEST_HOOKS=OFF
cmake --build build/local-core --target load_contract time_contract reset_contract bus_boundary_contract --parallel 2
ctest --test-dir build/local-core \
  -R '^(load_contract|time_contract|reset_contract|bus_boundary_contract)$' \
  --output-on-failure --no-tests=error
```

The focused core subset avoids the broader CTest roster, which includes game, MAME, and longer evidence checks. For pre-merge checks, see the repository's CI workflow. Broader lanes build native and sanitizer configurations, prepare evidence dependencies, and run separately scoped evidence; they are distinct from the fast contract gate and the four-test core subset. CMake, Ninja, a C17 compiler, and Python 3 are the only prerequisites for the focused build. No `act`, Docker, or added dependency is required for the commands in this guide.
