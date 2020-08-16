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
	oldVulns, oldAdvs := readFile(*oldBboltFile)
	newVulns, newAdvs := readFile(*newBboltFile)

	log.Printf("=== got %v vulnerabilities from old DB and %v from new DB ===", len(oldVulns), len(newVulns))
	for cveID, oldVuln := range oldVulns {
		newVuln, ok := newVulns[cveID]
		if !ok {
			log.Printf("vulnerability %s does not exist in new %v", cveID, oldVuln)
		} else if !reflect.DeepEqual(oldVuln, newVuln) {
			log.Printf("vulnerability %s is different", cveID)
		}
	}

	log.Printf("=== got %d advisories from old DB and %d from new DB ===", len(oldAdvs), len(newAdvs))
	for k, oldAdv := range oldAdvs {
		newAdv, ok := newAdvs[k]
		if !ok {
			log.Printf("advisory %s does not exist in new %v", k, oldAdv)
		} else if !reflect.DeepEqual(oldAdv, newAdv) {
			log.Printf("advisory %s is different", k)
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
