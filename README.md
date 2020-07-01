# tentacle-go
Tentacle-go implementation

The tentacle framework has been running in the production environment for a long time, this project is a verification project used to verify the feasibility of the multi-language implementation of the tentacle framework, while ensuring the performance of the implementation as much as possible, but will not do a wider range of performance optimization work.

## Development status

At present, example can communicate normally with the [Rust](https://github.com/driftluo/tentacle) version

## Usage

### Example

```bash
$ go build example/simple.go
$ ./simple server
```

On one terminal:

```bash
$ ./simple
```

Now you can see some data interaction information on the terminal.

### API

Most of the api implementations are similar to the Rust version, mainly considering the comparison of the production version, but the Go The implementation has been streamlined and adapted to the Go language.
