package server

func (c *Conn) handleAuthSwitchResponse() error {
	authData, err := c.readAuthSwitchRequestResponse()
	if err != nil {
		return err
	}

	return c.compareAuthData(c.authPluginName, authData)
}
