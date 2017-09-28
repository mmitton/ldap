Basic LDAP v3 functionality for the Go (Golang) programming language

# Required Libraries:

- [github.com/mmitton/asn1-ber](https://github.com/mmitton/asn1-ber)

# Working:

- Connecting to LDAP server
- Binding to LDAP server
- Searching for entries
- Compiling string filters to LDAP filters
- Paging Search Results
- Multiple internal goroutines to handle network traffic
  - Makes library goroutine safe
  - Can perform multiple search requests at the same time and return
    the results to the proper goroutine.  All requests are blocking
    requests, so the goroutine does not need special handling.

# Tests Implemented:

- Filter Compile / Decompile

# TODO:

-  Modify Requests / Responses
-  Add Requests / Responses
-  Delete Requests / Responses
-  Modify DN Requests / Responses
-  Compare Requests / Responses
-  Implement Tests / Benchmarks
