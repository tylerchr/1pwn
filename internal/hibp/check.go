package hibp

import (
	"bufio"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"net/http"
	"strconv"
	"strings"
)

// Checker provides a mechanism for looking up whether a password has been pwned.
//
// Checker is a struct instead of a function in order to provide a caching
// mechanism that avoids API requests for hashes that we already got an answer to.
type Checker struct {
	HTTPClient *http.Client

	prefix map[[5]byte]bool
	pwned  map[[sha1.Size]byte]int64
}

// Pwned looks up a count of how frequently the password exists in the HaveIBeenPwned
// database. A count of zero indicates that the password does not appear (whew).
func (c *Checker) Pwned(pwd string) int64 {

	sum := sha1.Sum([]byte(pwd))

	// ensure it's in cache
	if err := c.ensureCached(sum); err != nil {
		panic(err)
	}

	return c.pwned[sum]
}

// ensureCached populates the cache with the frequency for the given password SHA1.
//
// Due to the nature of the HIBP API, it also caches the frequencies for all other
// passwords with the same 5-character hash prefix in case those happen to be checked
// later.
func (c *Checker) ensureCached(sha [sha1.Size]byte) error {

	if c.HTTPClient == nil {
		c.HTTPClient = http.DefaultClient
	}

	if c.prefix == nil {
		c.prefix = make(map[[5]byte]bool)
	}

	if c.pwned == nil {
		c.pwned = make(map[[sha1.Size]byte]int64)
	}

	// determine hash prefix
	var prefix [5]byte
	hexprefix := strings.ToUpper(hex.EncodeToString(sha[:]))
	copy(prefix[:], []byte(hexprefix[0:5]))

	// we already checked this prefix
	if c.prefix[prefix] {
		return nil
	}

	req, _ := http.NewRequest("GET", "https://api.pwnedpasswords.com/range/"+hexprefix[0:5], nil)
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()

	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {

		parts := strings.Split(scanner.Text(), ":")
		if len(parts) != 2 {
			panic("not the right part count")
		}

		// reconstruct the overall hash
		hash, err := hex.DecodeString(scrub(hexprefix[0:5] + parts[0]))
		if err != nil {
			fmt.Println("problem here")
			panic(err)
		}
		count, err := strconv.ParseInt(parts[1], 10, 64)
		if err != nil {
			panic(err)
		}

		var key [sha1.Size]byte
		copy(key[:], hash)

		c.pwned[key] = count

	}

	c.prefix[prefix] = true

	return scanner.Err()

}

// scrub drops any non-alphanumeric characters from a string.
//
// I'm not sure why this is necessary, except that I kept getting responses
// back from the API that started with [ef bb bf] and that confused the hex
// parser as it's not real data. I added this and didn't investigate further.
func scrub(in string) string {
	s := []byte(in)
	out := make([]byte, 0, len(s))
	for _, c := range s {
		if (c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'Z') {
			out = append(out, c)
		}
	}
	return string(out)
}
