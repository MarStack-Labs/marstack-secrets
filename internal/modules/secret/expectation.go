package secret

type Expectation struct {
	enforced bool
	version  int
}

func Any() Expectation {
	return Expectation{}
}

func AtVersion(version int) Expectation {
	return Expectation{enforced: true, version: version}
}

func Absent() Expectation {
	return AtVersion(0)
}

func (e Expectation) satisfiedBy(current int) bool {
	return !e.enforced || e.version == current
}
