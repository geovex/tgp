package network_exchange

type dualstackError struct {
	prefix     string
	ipv4, ipv6 error
}

func (e *dualstackError) Error() string {
	result := e.prefix + " :"
	if e.ipv4 != nil {
		result += " v4: " + e.ipv4.Error()
	}
	if e.ipv6 != nil {
		result += " v6: " + e.ipv6.Error()
	}
	return result
}

func (e *dualstackError) Unwrap() []error {
	return []error{e.ipv4, e.ipv6}
}

func newDualstackError(prefix string, err4, err6 error) error {
	return &dualstackError{
		prefix: prefix,
		ipv4:   err4,
		ipv6:   err6,
	}
}
