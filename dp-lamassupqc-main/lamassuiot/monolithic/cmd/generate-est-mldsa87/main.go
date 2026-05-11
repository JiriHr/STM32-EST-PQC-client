package main

import (
	"context"

	"github.com/lamassuiot/lamassuiot/monolithic/v3/pkg/estmldsapoc"
)

func main() {
	if err := estmldsapoc.Run(context.Background(), estmldsapoc.MLDSA87); err != nil {
		panic(err)
	}
}
