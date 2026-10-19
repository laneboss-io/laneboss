package dashboard

import "laneboss.io/laneboss/internal/config"

func configForGroups(name string) (*config.Configuration, error) { return config.Load(name) }
