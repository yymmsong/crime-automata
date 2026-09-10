package main

import (
	"bufio"
	"compress/zlib"
	"flag"
	"io"
	"os"
)

func main() {
	decompPtr := flag.Bool("d", false, "decompress")
	level := flag.Int("level", 0, "compression level")

	flag.Parse()

	if *decompPtr {
		zlibReader, err := zlib.NewReader(bufio.NewReader(os.Stdin))
		if err != nil {
			panic(err)
		}

		io.Copy(os.Stdout, zlibReader)
		zlibReader.Close()
	} else {
		reader, writer := io.Pipe()

		go func() {
			zlibWriter, err := zlib.NewWriterLevel(writer, *level)
			if err != nil {
				panic(err)
			}
			io.Copy(zlibWriter, os.Stdin)
			zlibWriter.Close()
			writer.Close()
		}()

		io.Copy(os.Stdout, reader)
		reader.Close()
	}
}
