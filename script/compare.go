package main

import (
	"flag"
	"fmt"
	bolt "go.etcd.io/bbolt"
	"log"
	"reflect"
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
	if !reflect.DeepEqual(oldVuln, newVuln) {
		fmt.Printf("got %v vulnerabilities from old DB and %v from new DB\n", len(oldVuln), len(newVuln))
		for k := range oldVuln {
			if _, ok := newVuln[k]; !ok {
				fmt.Printf("vulnerability %v does not exist in new %v", k, oldVuln[k])
			}
		}
	}
	if !reflect.DeepEqual(oldAdvis, newAdv) {
		fmt.Printf("got %v advisories from old DB and %v from new DB\n", len(oldAdvis), len(newAdv))
		for k := range oldAdvis {
			if _, ok := newAdv[k]; !ok {
				fmt.Printf("advisory %v does not exist in new: %v", k, oldAdvis[k])
			}
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
