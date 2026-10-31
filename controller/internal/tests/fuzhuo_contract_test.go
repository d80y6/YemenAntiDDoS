package tests

func (b *mockContractBackend) SetAnnouncement(id, refcount int, status string) error {
	b.ms.bgpAnnouncements.fzSet(id, refcount, status)
	return nil
}
