//go:build windows

package backup

import (
	"path/filepath"
	"testing"
)

func TestSafeJoinRejectsTraversal(t *testing.T) {
	root := filepath.Join("C://", "Windows", "Temp", "opencert-test")
	bad := []string{"../evil.txt", "..\\evil.txt", "a/../../evil.txt", "C://Windows//evil.txt"}
	for _, rel := range bad {
		if _, err := safeJoin(root, rel); err == nil {
			t.Fatalf("safeJoin accepted %q", rel)
		}
	}
	good, err := safeJoin(root, "0000/keymaps")
	if err != nil {
		t.Fatalf("safeJoin rejected valid path: %v", err)
	}
	want := filepath.Join(root, "0000", "keymaps")
	if good != want {
		t.Fatalf("safeJoin = %q, want %q", good, want)
	}
}
