package main

import "embed"

//go:embed all:console/dist
var webDist embed.FS

const webRoot = "console/dist"
