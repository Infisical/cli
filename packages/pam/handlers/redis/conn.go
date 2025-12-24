package redis

import (
	"net"

	"github.com/smallnest/resp3"
)

type RedisConn struct {
	conn   net.Conn
	reader *resp3.Reader
	writer *resp3.Writer
}

func NewRedisConn(conn net.Conn) *RedisConn {
	return &RedisConn{
		conn:   conn,
		reader: resp3.NewReader(conn),
		writer: resp3.NewWriter(conn),
	}
}

func (c *RedisConn) Close() error {
	return c.conn.Close()
}

func (c *RedisConn) Reader() *resp3.Reader {
	return c.reader
}

func (c *RedisConn) Writer() *resp3.Writer {
	return c.writer
}

func (c *RedisConn) WriteValue(value resp3.Value) error {
	_, err := c.writer.WriteString(value.ToRESP3String())
	return err
}
