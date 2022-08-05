package gokrb5

// #include <krb5.h>
import "C"

import (
	"runtime"
	"time"
)

type Creds struct {
	c *Context
	p *C.krb5_creds // NOT a pointer type.
}

func newCredsFromC(c *Context, p *C.krb5_creds) *Creds {
	cp := &Creds{c, p}
	runtime.SetFinalizer(cp, (*Creds).free)
	return cp
}

func newCredsFromGo(c *Context, p *C.krb5_creds) *Creds {
	cp := &Creds{c, p}
	runtime.SetFinalizer(cp, (*Creds).freeContents)
	return cp
}

func (c *Creds) freeContents() {
	if c.p != nil {
		C.krb5_free_cred_contents(c.c.toC(), c.p)
	}
}

func (c *Creds) free() {
	if c.p != nil {
		C.krb5_free_creds(c.c.toC(), c.p)
		c.p = nil
	}
}

func (c *Creds) StartTime() int32 {
	return int32(c.p.times.starttime)
}

func (c *Creds) Start() time.Time {
	return time.Unix(int64(c.StartTime()), 0)
}

func (c *Creds) EndTime() int32 {
	return int32(c.p.times.endtime)
}

func (c *Creds) End() time.Time {
	return time.Unix(int64(c.EndTime()), 0)
}

func (c *Creds) RenewUntilTime() int32 {
	return int32(c.p.times.renew_till)
}

func (c *Creds) RenewUntil() time.Time {
	return time.Unix(int64(c.RenewUntilTime()), 0)
}

func (c *Creds) Expired() bool {
	if c.StartTime() == 0 {
		return false
	}
	return time.Now().After(c.End())
}

func (c *Creds) Server() (*Principal, error) {
	var cp C.krb5_principal
	code := C.krb5_copy_principal(c.c.toC(), c.p.server, &cp)
	if code != 0 {
		return nil, ErrorCode(code)
	}
	return newPrincipalFromC(c.c, cp), nil
}

func (c *Creds) Client() (*Principal, error) {
	var cp C.krb5_principal
	code := C.krb5_copy_principal(c.c.toC(), c.p.client, &cp)
	if code != 0 {
		return nil, ErrorCode(code)
	}
	return newPrincipalFromC(c.c, cp), nil
}

func (c *Creds) IsLocalTgt(realm string) (bool, error) {
	srvPrincipal, err := c.Server()
	if err != nil {
		return false, err
	}
	srvName := srvPrincipal.Name()
	if len(srvName) == 2 &&
		srvPrincipal.Realm() == realm &&
		srvName[0] == "krbtgt" &&
		srvName[1] == realm {
		return true, nil
	}
	return false, nil
}
