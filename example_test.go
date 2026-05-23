package portcullis_test

import (
	"fmt"

	"github.com/docker/portcullis"
)

func ExampleRedact() {
	log := "Run this with token=ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA1yBYBE please."

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
	in := "first ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA1yBYBE " +
		"and second ghp_BBBBBBBBBBBBBBBBBBBBBBBBBBBBBB1794Fj end"

	fmt.Println(portcullis.Redact(in))
	// Output:
	// first [REDACTED] and second [REDACTED] end
}

func ExampleContains() {
	fmt.Println(portcullis.Contains("hello world"))
	fmt.Println(portcullis.Contains("token=ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA1yBYBE"))
	// Output:
	// false
	// true
}

func ExampleFind() {
	in := "first ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA1yBYBE then " +
		"postgresql://app:hunter2supersecret@db.internal/orders"

	for _, m := range portcullis.Find(in) {
		fmt.Printf("%d-%d: %s\n", m.Start, m.End, m.Value)
	}
	// Output:
	// 6-46: ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA1yBYBE
	// 69-87: hunter2supersecret
}
