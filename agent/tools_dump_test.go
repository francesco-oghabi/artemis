package agent

import (
	"reflect"
	"testing"
)

func TestBetweenAll(t *testing.T) {
	got := betweenAll(`x<S>a<E>y<S>b<E>z`, "<S>", "<E>")
	if !reflect.DeepEqual(got, []string{"a", "b"}) {
		t.Fatalf("betweenAll = %v", got)
	}
	if len(betweenAll("no markers", "<S>", "<E>")) != 0 {
		t.Fatal("betweenAll should be empty when no markers")
	}
}

func TestOrderPositions(t *testing.T) {
	// non-zero columns first (the id/first column is type-sensitive), then 0.
	if got := orderPositions([]int{0, 1, 2}); !reflect.DeepEqual(got, []int{1, 2, 0}) {
		t.Fatalf("orderPositions = %v", got)
	}
}

// TestSchemaRegexes locks that table/column resolution matches names that START with
// the keyword (the bug: "Users" / "email" with no prefix char must still match).
func TestSchemaRegexes(t *testing.T) {
	if sqlUserTableRe.FindString("Addresses,Baskets,Users,Wallets") != "Users" {
		t.Fatalf("user table: %q", sqlUserTableRe.FindString("Addresses,Baskets,Users,Wallets"))
	}
	cols := "`id` INTEGER, `username` VARCHAR, `email` VARCHAR, `password` VARCHAR"
	if sqlMailColRe.FindString(cols) != "email" {
		t.Fatalf("mail col: %q", sqlMailColRe.FindString(cols))
	}
	if sqlPassColRe.FindString(cols) != "password" {
		t.Fatalf("pass col: %q", sqlPassColRe.FindString(cols))
	}
}
