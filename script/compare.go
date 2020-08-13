package main

import (
	"flag"
	"fmt"
	"log"
	"reflect"

	bolt "go.etcd.io/bbolt"
)

const (
	vulnerabilityBucket = "vulnerability"
)

var (
	oldBboltFile = flag.String("old_file", "cache/db/old.db", "old DB file")
	newBboltFile = flag.String("new_file", "cache/db/trivy.db", "new DB file")
)

func main() {
	flag.Parse()
	oldVuln, oldAdvis := readFile(*oldBboltFile)
	newVuln, newAdv := readFile(*newBboltFile)

	fmt.Printf("=== got %v vulnerabilities from old DB and %v from new DB ===\n", len(oldVuln), len(newVuln))
	for k, old := range oldVuln {
		new, ok := newVuln[k]
		if !ok {
			fmt.Printf("vulnerability %s does not exist in new %v\n", k, old)
		} else if !reflect.DeepEqual(old, new) {
			fmt.Printf("vulnerability %s is different\n", k)
		}
	}

	fmt.Printf("=== got %d advisories from old DB and %d from new DB ===\n", len(oldAdvis), len(newAdv))
	for k, old := range oldAdvis {
		new, ok := newAdv[k]
		if !ok {
			fmt.Printf("advisory %s does not exist in new %v\n", k, old)
		} else if !reflect.DeepEqual(old, new) {
			fmt.Printf("advisory %s is different\n", k)
		}
	}
}

func readFile(file string) (vulnerabilities, advisories map[string]string) {
	vulnerabilities = make(map[string]string)
	advisories = make(map[string]string)
	db, err := bolt.Open(file, 0600, nil)
	if err != nil {
		return
	}
	defer db.Close()
	err = db.View(func(tx *bolt.Tx) error {
		return tx.ForEach(func(name []byte, b *bolt.Bucket) error {
			if string(name) == vulnerabilityBucket {
				err = b.ForEach(func(k, v []byte) error {
					if len(string(k)) > 3 {
						vulnerabilities[string(k)] = string(v)
					}
					return nil
				})
			} else {
				tx.Bucket(name).ForEach(func(nestedBucket, _ []byte) error {
					tx.Bucket(name).Bucket(nestedBucket).ForEach(func(k, v []byte) error {
						advisories[fmt.Sprintf("%v:%v:%v", string(name), string(nestedBucket), string(k))] = string(v)
						return nil
					})
					return nil
				})
			}
			return nil
		})
	})
	if err != nil {
		log.Fatal(err)
	}
	return
}
