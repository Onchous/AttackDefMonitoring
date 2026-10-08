package query

import "testing"

func TestCaptureChainWindowQuery(t *testing.T) {
	queries := []string{
		`@seed:id:42 chost:10.10.1.2 ftime:"@seed:ftime@-31s:@seed:ftime@+31s" sort:ftime,id`,
		`@seed:id:42 chost:2001:db8::10 ftime:"@seed:ftime@-31s:@seed:ftime@+31s" sort:ftime,id`,
	}
	for _, text := range queries {
		if _, err := Parse(text); err != nil {
			t.Errorf("failed to parse chain query %q: %v", text, err)
		}
	}
}
