package action

// Guards that lookup failures keep the HEAD error wrapping (%w), so callers can
// still match the repository error. Adapted from the cut 11i blind review probe.

import (
	"context"
	"errors"
	"testing"

	"github.com/d80y6/YemenDDoS/controller/internal/store"
)

type dao11iErrStore struct {
	store.Store
	shell      dao11iShellRepo
	targets    dao11iTargetsRepo
	connectors dao11iConnectorsRepo
}

func (s dao11iErrStore) ShellConnectors() store.ShellConnectorRepo { return s.shell }
func (s dao11iErrStore) XDropTargets() store.XDropTargetRepo       { return s.targets }
func (s dao11iErrStore) XDropConnectors() store.XDropConnectorRepo { return s.connectors }

type dao11iShellRepo struct {
	store.ShellConnectorRepo
	err error
}

func (s dao11iShellRepo) Get(context.Context, int) (*store.ShellConnector, error) { return nil, s.err }

type dao11iTargetsRepo struct {
	store.XDropTargetRepo
	err error
}

func (s dao11iTargetsRepo) List(context.Context, int) ([]store.XDropConnector, error) {
	return nil, s.err
}

type dao11iConnectorsRepo struct {
	store.XDropConnectorRepo
	err error
}

func (s dao11iConnectorsRepo) ListEnabled(context.Context) ([]store.XDropConnector, error) {
	return nil, s.err
}

func TestDao11i_LookupErrorChain(t *testing.T) {
	for _, name := range []string{"Shell", "Targets", "Enabled"} {
		t.Run(name, func(t *testing.T) {
			sentinel := errors.New("dao11i repository error")
			s := dao11iErrStore{}
			id := 7
			act := store.ResponseAction{ID: 10, ShellConnectorID: &id, XDropAction: "drop"}
			var row *store.ActionExecutionLog
			var err error
			switch name {
			case "Shell":
				s.shell.err = sentinel
				row, err = executeShell(context.Background(), s, act, nil, "confirmed", "192.0.2.10", "dao11i", "on_detected", 20, nil)
			case "Targets":
				s.targets.err = sentinel
				row, err = executeXDrop(context.Background(), s, act, nil, "confirmed", "192.0.2.10", "dao11i", "on_detected", 20, nil, nil)
			case "Enabled":
				s.connectors.err = sentinel
				row, err = executeXDrop(context.Background(), s, act, nil, "confirmed", "192.0.2.10", "dao11i", "on_detected", 20, nil, nil)
			}
			if err == nil {
				t.Fatal("missing lookup error")
			}
			matches := errors.Is(err, sentinel)
			direct := errors.Unwrap(err) == sentinel
			t.Logf("ASSERT G4.%s.ErrorChain is=%v unwrapSame=%v err=%q", name, matches, direct, err.Error())
			if !matches || !direct {
				t.Errorf("ASSERT G4.%s.ErrorChain FAIL", name)
			}
			if row != nil && row.ErrorMessage != err.Error() {
				t.Errorf("row message differs: %q / %q", row.ErrorMessage, err.Error())
			}
		})
	}
}
