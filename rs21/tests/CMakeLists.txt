add_test(NAME rs21_demo_runs COMMAND rs21_demo)
set_tests_properties(rs21_demo_runs PROPERTIES PASS_REGULAR_EXPRESSION "2026")
