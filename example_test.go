package portcullis_test

import (
	"fmt"

	"github.com/docker/portcullis"
)

// ghpFixture is a syntactically valid GitHub PAT (correct CRC32 over the
// 30-char body), built at runtime so the literal token never appears on a
// single source line — push protection would otherwise reject the push.
var ghpFixture = "ghp_" + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" + "0uCPlr"

func ExampleRedact() {
	log := "Run this with token=" + ghpFixture + " please."

	fmt.Println(portcullis.Redact(log))
	// Output:
	// Run this with token=[REDACTED] please.
}

func ExampleRedact_connectionString() {
	// Connection-string rules redact only the password span so the
	// surrounding URL stays useful for log readers.
	uri := "postgresql://app:hunter2supersecret@db.internal:5432/orders"

	fmt.Println(portcullis.Redact(uri))
	// Output:
	// postgresql://app:[REDACTED]@db.internal:5432/orders
}

func ExampleRedact_multipleSecrets() {
	other := "ghp_" + "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBB" + "1rpRcy"
	in := "first " + ghpFixture + " and second " + other + " end"

	fmt.Println(portcullis.Redact(in))
	// Output:
	// first [REDACTED] and second [REDACTED] end
}

func ExampleContains() {
	fmt.Println(portcullis.Contains("hello world"))
	fmt.Println(portcullis.Contains("token=" + ghpFixture))
	// Output:
	// false
	// true
}

func ExampleFind() {
	// Demonstrated with an AWS access key + a Postgres password so the
	// expected-output comment doesn't have to contain a checksum-valid
	// GitHub PAT (which push protection would block).
	awsKey := "AKIA" + "RZPUZDIKQEXAMPLE"
	in := "first " + awsKey + " then " +
		"postgresql://app:hunter2supersecret@db.internal/orders"

	for _, m := range portcullis.Find(in) {
		fmt.Printf("%d-%d: %s\n", m.Start, m.End, m.Value)
	}
	// Output:
	// 6-26: AKIARZPUZDIKQEXAMPLE
	// 49-67: hunter2supersecret
}
