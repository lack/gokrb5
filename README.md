# gokrb5

A thin CGO wrapper around MIT libkrb5

The wrapper follows the MIT API, making the primary C objects into Go objects.

http://web.mit.edu/kerberos/krb5-current/doc/appldev/refs/api/index.html

This was forked from One-com/gokrb5 to update, modernizeand extend

## Using

```go
import "github.com/lack/gokrb5"
```

## Testing

Tests needs to be run with faketime:

```shell
go test -v -exec 'faketime "2008-12-24 08:15:42"'
```

