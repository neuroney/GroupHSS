add_test(NAME osy21_demo_runs COMMAND osy21_demo)
set_tests_properties(osy21_demo_runs PROPERTIES PASS_REGULAR_EXPRESSION "2026")
