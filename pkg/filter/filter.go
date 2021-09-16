package filter

import (
	"golang.org/x/tools/go/callgraph"
	"regexp"
	"strings"
)

var (
	// Hacked this array together using:
	// $ go version
	// go version go1.17 linux/amd64
	// $ find /usr/local/go/src/ -type d | sed 's/\/usr\/local\/go\/src\///'  | sed 's/^vendor\///' | sed 's/cmd\/vendor\///' > pkgs
	// $ for line in $(cat pkgs); do printf "\"%s\"," $line; done
	stdlib = []string {
		"syscall","syscall/js","context","builtin","expvar","testing","testing/quick","testing/fstest","testing/internal","testing/internal/testdeps","testing/iotest","os","os/signal","os/signal/internal","os/signal/internal/pty","os/user","os/testdata","os/testdata/issue37161","os/testdata/dirfs","os/testdata/dirfs/dir","os/exec","index","index/suffixarray","text","text/tabwriter","text/scanner","text/template","text/template/parse","text/template/testdata","plugin","errors","sync","sync/atomic","html","html/template","html/template/testdata","runtime","runtime/debug","runtime/cgo","runtime/race","runtime/race/testdata","runtime/trace","runtime/metrics","runtime/msan","runtime/testdata","runtime/testdata/testwinsignal","runtime/testdata/testfaketime","runtime/testdata/testwinlib","runtime/testdata/testprognet","runtime/testdata/testprog","runtime/testdata/testprogcgo","runtime/testdata/testprogcgo/windows","runtime/testdata/testwinlibsignal","runtime/pprof","runtime/pprof/testdata","runtime/pprof/testdata/mappingtest","runtime/internal","runtime/internal/math","runtime/internal/atomic","runtime/internal/sys","encoding","encoding/base32","encoding/asn1","encoding/json","encoding/json/testdata","encoding/gob","encoding/hex","encoding/xml","encoding/pem","encoding/binary","encoding/base64","encoding/ascii85","encoding/csv","math","math/cmplx","math/big","math/bits","math/rand","debug","debug/macho","debug/macho/testdata","debug/elf","debug/elf/testdata","debug/plan9obj","debug/plan9obj/testdata","debug/pe","debug/pe/testdata","debug/dwarf","debug/dwarf/testdata","debug/gosym","debug/gosym/testdata","fmt","flag","go","go/importer","go/token","go/constant","go/ast","go/parser","go/parser/testdata","go/parser/testdata/issue42951","go/parser/testdata/issue42951/not_a_file.go","go/parser/testdata/resolution","go/format","go/scanner","go/build","go/build/testdata","go/build/testdata/empty","go/build/testdata/other","go/build/testdata/other/file","go/build/testdata/multi","go/build/testdata/withvendor","go/build/testdata/withvendor/src","go/build/testdata/withvendor/src/a","go/build/testdata/withvendor/src/a/b","go/build/testdata/withvendor/src/a/vendor","go/build/testdata/withvendor/src/a/vendor/c","go/build/testdata/withvendor/src/a/vendor/c/d","go/build/testdata/cgo_disabled","go/build/testdata/doc","go/build/constraint","go/printer","go/printer/testdata","go/internal","go/internal/typeparams","go/internal/gccgoimporter","go/internal/gccgoimporter/testdata","go/internal/gcimporter","go/internal/gcimporter/testdata","go/internal/gcimporter/testdata/versions","go/internal/srcimporter","go/internal/srcimporter/testdata","go/internal/srcimporter/testdata/issue24392","go/internal/srcimporter/testdata/issue23092","go/internal/srcimporter/testdata/issue20855","go/types","go/types/testdata","go/types/testdata/examples","go/types/testdata/fixedbugs","go/types/testdata/check","go/types/testdata/check/importdecl0","go/types/testdata/check/issue25008","go/types/testdata/check/decls2","go/types/testdata/check/importdecl1","go/doc","go/doc/testdata","bufio","mime","mime/multipart","mime/multipart/testdata","mime/quotedprintable","mime/testdata","time","time/testdata","time/tzdata","image","image/gif","image/png","image/png/testdata","image/png/testdata/pngsuite","image/draw","image/testdata","image/jpeg","image/internal","image/internal/imageutil","image/color","image/color/palette","embed","embed/internal","embed/internal/embedtest","embed/internal/embedtest/testdata","embed/internal/embedtest/testdata/i","embed/internal/embedtest/testdata/i/j","embed/internal/embedtest/testdata/i/j/k","embed/internal/embedtest/testdata/_hidden","embed/internal/embedtest/testdata/.hidden","embed/internal/embedtest/testdata/.hidden/_more","embed/internal/embedtest/testdata/.hidden/.more","embed/internal/embedtest/testdata/.hidden/more","embed/internal/embedtest/testdata/-not-hidden","regexp","regexp/testdata","regexp/syntax","reflect","reflect/internal","reflect/internal/example1","reflect/internal/example2","log","log/syslog","strconv","strconv/testdata","cmd","cmd/dist","cmd/objdump","cmd/objdump/testdata","cmd/objdump/testdata/testfilenum","cmd/cover","cmd/cover/testdata","cmd/cover/testdata/html","cmd/compile","cmd/compile/internal","cmd/compile/internal/base","cmd/compile/internal/devirtualize","cmd/compile/internal/mips","cmd/compile/internal/staticdata","cmd/compile/internal/importer","cmd/compile/internal/importer/testdata","cmd/compile/internal/importer/testdata/versions","cmd/compile/internal/escape","cmd/compile/internal/abi","cmd/compile/internal/bitvec","cmd/compile/internal/inline","cmd/compile/internal/mips64","cmd/compile/internal/x86","cmd/compile/internal/walk","cmd/compile/internal/wasm","cmd/compile/internal/objw","cmd/compile/internal/riscv64","cmd/compile/internal/logopt","cmd/compile/internal/dwarfgen","cmd/compile/internal/arm64","cmd/compile/internal/typebits","cmd/compile/internal/staticinit","cmd/compile/internal/deadcode","cmd/compile/internal/ppc64","cmd/compile/internal/s390x","cmd/compile/internal/gc","cmd/compile/internal/arm","cmd/compile/internal/reflectdata","cmd/compile/internal/ssa","cmd/compile/internal/ssa/gen","cmd/compile/internal/ssa/testdata","cmd/compile/internal/ir","cmd/compile/internal/liveness","cmd/compile/internal/ssagen","cmd/compile/internal/pkginit","cmd/compile/internal/noder","cmd/compile/internal/typecheck","cmd/compile/internal/typecheck/builtin","cmd/compile/internal/types2","cmd/compile/internal/types2/testdata","cmd/compile/internal/types2/testdata/examples","cmd/compile/internal/types2/testdata/fixedbugs","cmd/compile/internal/types2/testdata/check","cmd/compile/internal/types2/testdata/check/importdecl0","cmd/compile/internal/types2/testdata/check/issue25008","cmd/compile/internal/types2/testdata/check/decls2","cmd/compile/internal/types2/testdata/check/importdecl1","cmd/compile/internal/amd64","cmd/compile/internal/test","cmd/compile/internal/test/testdata","cmd/compile/internal/test/testdata/gen","cmd/compile/internal/test/testdata/reproducible","cmd/compile/internal/types","cmd/compile/internal/syntax","cmd/compile/internal/syntax/testdata","cmd/compile/internal/syntax/testdata/go2","cmd/api","cmd/api/testdata","cmd/api/testdata/src","cmd/api/testdata/src/issue21181","cmd/api/testdata/src/issue21181/indirect","cmd/api/testdata/src/issue21181/dep","cmd/api/testdata/src/issue21181/p","cmd/api/testdata/src/pkg","cmd/api/testdata/src/pkg/p3","cmd/api/testdata/src/pkg/p2","cmd/api/testdata/src/pkg/p1","cmd/api/testdata/src/issue29837","cmd/api/testdata/src/issue29837/p","cmd/addr2line","cmd/asm","cmd/asm/internal","cmd/asm/internal/lex","cmd/asm/internal/flags","cmd/asm/internal/asm","cmd/asm/internal/asm/testdata","cmd/asm/internal/asm/testdata/avx512enc","cmd/asm/internal/arch","cmd/buildid","cmd/gofmt","cmd/gofmt/testdata","cmd/cgo","cmd/go","cmd/go/testdata","cmd/go/testdata/script","cmd/go/testdata/testterminal18153","cmd/go/testdata/modlegacy","cmd/go/testdata/modlegacy/src","cmd/go/testdata/modlegacy/src/old","cmd/go/testdata/modlegacy/src/old/p2","cmd/go/testdata/modlegacy/src/old/p1","cmd/go/testdata/modlegacy/src/new","cmd/go/testdata/modlegacy/src/new/sub","cmd/go/testdata/modlegacy/src/new/sub/x","cmd/go/testdata/modlegacy/src/new/sub/x/v1","cmd/go/testdata/modlegacy/src/new/sub/x/v1/y","cmd/go/testdata/modlegacy/src/new/sub/inner","cmd/go/testdata/modlegacy/src/new/sub/inner/x","cmd/go/testdata/modlegacy/src/new/p2","cmd/go/testdata/modlegacy/src/new/p1","cmd/go/testdata/mod","cmd/go/testdata/failssh","cmd/go/internal","cmd/go/internal/base","cmd/go/internal/imports","cmd/go/internal/imports/testdata","cmd/go/internal/imports/testdata/android","cmd/go/internal/imports/testdata/star","cmd/go/internal/imports/testdata/illumos","cmd/go/internal/modfetch","cmd/go/internal/modfetch/zip_sum_test","cmd/go/internal/modfetch/zip_sum_test/testdata","cmd/go/internal/modfetch/codehost","cmd/go/internal/modconv","cmd/go/internal/modconv/testdata","cmd/go/internal/work","cmd/go/internal/run","cmd/go/internal/mvs","cmd/go/internal/search","cmd/go/internal/fmtcmd","cmd/go/internal/lockedfile","cmd/go/internal/lockedfile/internal","cmd/go/internal/lockedfile/internal/filelock","cmd/go/internal/vcs","cmd/go/internal/envcmd","cmd/go/internal/fix","cmd/go/internal/web","cmd/go/internal/trace","cmd/go/internal/modinfo","cmd/go/internal/list","cmd/go/internal/get","cmd/go/internal/load","cmd/go/internal/auth","cmd/go/internal/robustio","cmd/go/internal/str","cmd/go/internal/cache","cmd/go/internal/modget","cmd/go/internal/fsys","cmd/go/internal/generate","cmd/go/internal/version","cmd/go/internal/modcmd","cmd/go/internal/modload","cmd/go/internal/par","cmd/go/internal/vet","cmd/go/internal/test","cmd/go/internal/help","cmd/go/internal/cmdflag","cmd/go/internal/clean","cmd/go/internal/bug","cmd/go/internal/doc","cmd/go/internal/txtar","cmd/go/internal/cfg","cmd/go/internal/tool","cmd/test2json","cmd/pack","cmd/fix","cmd/trace","cmd/link","cmd/link/testdata","cmd/link/testdata/pe-binutils","cmd/link/testdata/testBuildFortvOS","cmd/link/testdata/testRO","cmd/link/testdata/testHashedSyms","cmd/link/testdata/testIndexMismatch","cmd/link/testdata/pe-llvm","cmd/link/internal","cmd/link/internal/mips","cmd/link/internal/loader","cmd/link/internal/mips64","cmd/link/internal/x86","cmd/link/internal/wasm","cmd/link/internal/riscv64","cmd/link/internal/loadelf","cmd/link/internal/arm64","cmd/link/internal/ld","cmd/link/internal/ld/testdata","cmd/link/internal/ld/testdata/httptest","cmd/link/internal/ld/testdata/httptest/main","cmd/link/internal/ld/testdata/issue32233","cmd/link/internal/ld/testdata/issue32233/lib","cmd/link/internal/ld/testdata/issue32233/main","cmd/link/internal/ld/testdata/issue38192","cmd/link/internal/ld/testdata/issue10978","cmd/link/internal/ld/testdata/issue39757","cmd/link/internal/ld/testdata/deadcode","cmd/link/internal/ld/testdata/issue25459","cmd/link/internal/ld/testdata/issue25459/a","cmd/link/internal/ld/testdata/issue25459/main","cmd/link/internal/ld/testdata/issue42484","cmd/link/internal/ld/testdata/issue39256","cmd/link/internal/ld/testdata/issue26237","cmd/link/internal/ld/testdata/issue26237/main","cmd/link/internal/ld/testdata/issue26237/b.dir","cmd/link/internal/ppc64","cmd/link/internal/s390x","cmd/link/internal/loadxcoff","cmd/link/internal/arm","cmd/link/internal/benchmark","cmd/link/internal/loadpe","cmd/link/internal/loadmacho","cmd/link/internal/amd64","cmd/link/internal/sym","cmd/vet","cmd/vet/testdata","cmd/vet/testdata/httpresponse","cmd/vet/testdata/structtag","cmd/vet/testdata/composite","cmd/vet/testdata/asm","cmd/vet/testdata/atomic","cmd/vet/testdata/cgo","cmd/vet/testdata/tagtest","cmd/vet/testdata/testingpkg","cmd/vet/testdata/method","cmd/vet/testdata/print","cmd/vet/testdata/deadcode","cmd/vet/testdata/rangeloop","cmd/vet/testdata/unmarshal","cmd/vet/testdata/assign","cmd/vet/testdata/copylock","cmd/vet/testdata/nilfunc","cmd/vet/testdata/buildtag","cmd/vet/testdata/shift","cmd/vet/testdata/bool","cmd/vet/testdata/unsafeptr","cmd/vet/testdata/unused","cmd/vet/testdata/lostcancel","cmd/vendor","github.com","github.com/google","github.com/google/pprof","github.com/google/pprof/driver","github.com/google/pprof/third_party","github.com/google/pprof/third_party/d3flamegraph","github.com/google/pprof/third_party/svgpan","github.com/google/pprof/third_party/d3","github.com/google/pprof/internal","github.com/google/pprof/internal/measurement","github.com/google/pprof/internal/binutils","github.com/google/pprof/internal/plugin","github.com/google/pprof/internal/driver","github.com/google/pprof/internal/graph","github.com/google/pprof/internal/transport","github.com/google/pprof/internal/symbolz","github.com/google/pprof/internal/report","github.com/google/pprof/internal/symbolizer","github.com/google/pprof/internal/elfexec","github.com/google/pprof/profile","github.com/ianlancetaylor","github.com/ianlancetaylor/demangle","golang.org","golang.org/x","golang.org/x/tools","golang.org/x/tools/cover","golang.org/x/tools/go","golang.org/x/tools/go/ast","golang.org/x/tools/go/ast/astutil","golang.org/x/tools/go/ast/inspector","golang.org/x/tools/go/analysis","golang.org/x/tools/go/analysis/unitchecker","golang.org/x/tools/go/analysis/passes","golang.org/x/tools/go/analysis/passes/httpresponse","golang.org/x/tools/go/analysis/passes/structtag","golang.org/x/tools/go/analysis/passes/composite","golang.org/x/tools/go/analysis/passes/unusedresult","golang.org/x/tools/go/analysis/passes/sigchanyzer","golang.org/x/tools/go/analysis/passes/ctrlflow","golang.org/x/tools/go/analysis/passes/stdmethods","golang.org/x/tools/go/analysis/passes/stringintconv","golang.org/x/tools/go/analysis/passes/cgocall","golang.org/x/tools/go/analysis/passes/atomic","golang.org/x/tools/go/analysis/passes/framepointer","golang.org/x/tools/go/analysis/passes/testinggoroutine","golang.org/x/tools/go/analysis/passes/loopclosure","golang.org/x/tools/go/analysis/passes/unmarshal","golang.org/x/tools/go/analysis/passes/assign","golang.org/x/tools/go/analysis/passes/unreachable","golang.org/x/tools/go/analysis/passes/copylock","golang.org/x/tools/go/analysis/passes/bools","golang.org/x/tools/go/analysis/passes/asmdecl","golang.org/x/tools/go/analysis/passes/nilfunc","golang.org/x/tools/go/analysis/passes/tests","golang.org/x/tools/go/analysis/passes/printf","golang.org/x/tools/go/analysis/passes/buildtag","golang.org/x/tools/go/analysis/passes/internal","golang.org/x/tools/go/analysis/passes/internal/analysisutil","golang.org/x/tools/go/analysis/passes/errorsas","golang.org/x/tools/go/analysis/passes/shift","golang.org/x/tools/go/analysis/passes/inspect","golang.org/x/tools/go/analysis/passes/ifaceassert","golang.org/x/tools/go/analysis/passes/unsafeptr","golang.org/x/tools/go/analysis/passes/lostcancel","golang.org/x/tools/go/analysis/internal","golang.org/x/tools/go/analysis/internal/analysisflags","golang.org/x/tools/go/analysis/internal/facts","golang.org/x/tools/go/types","golang.org/x/tools/go/types/typeutil","golang.org/x/tools/go/types/objectpath","golang.org/x/tools/go/cfg","golang.org/x/tools/internal","golang.org/x/tools/internal/analysisinternal","golang.org/x/tools/internal/lsp","golang.org/x/tools/internal/lsp/fuzzy","golang.org/x/mod","golang.org/x/mod/zip","golang.org/x/mod/module","golang.org/x/mod/modfile","golang.org/x/mod/semver","golang.org/x/mod/internal","golang.org/x/mod/internal/lazyregexp","golang.org/x/mod/sumdb","golang.org/x/mod/sumdb/dirhash","golang.org/x/mod/sumdb/note","golang.org/x/mod/sumdb/tlog","golang.org/x/arch","golang.org/x/arch/x86","golang.org/x/arch/x86/x86asm","golang.org/x/arch/arm64","golang.org/x/arch/arm64/arm64asm","golang.org/x/arch/ppc64","golang.org/x/arch/ppc64/ppc64asm","golang.org/x/arch/arm","golang.org/x/arch/arm/armasm","golang.org/x/xerrors","golang.org/x/xerrors/internal","golang.org/x/term","golang.org/x/crypto","golang.org/x/crypto/ed25519","golang.org/x/crypto/ed25519/internal","golang.org/x/crypto/ed25519/internal/edwards25519","golang.org/x/sys","golang.org/x/sys/windows","golang.org/x/sys/plan9","golang.org/x/sys/unix","golang.org/x/sys/internal","golang.org/x/sys/internal/unsafeheader","cmd/pprof","cmd/pprof/testdata","cmd/internal","cmd/internal/edit","cmd/internal/objabi","cmd/internal/diff","cmd/internal/buildid","cmd/internal/buildid/testdata","cmd/internal/browser","cmd/internal/src","cmd/internal/bio","cmd/internal/goobj","cmd/internal/moddeps","cmd/internal/test2json","cmd/internal/test2json/testdata","cmd/internal/objfile","cmd/internal/dwarf","cmd/internal/traceviewer","cmd/internal/codesign","cmd/internal/archive","cmd/internal/archive/testdata","cmd/internal/archive/testdata/mycgo","cmd/internal/pkgpath","cmd/internal/obj","cmd/internal/obj/mips","cmd/internal/obj/x86","cmd/internal/obj/wasm","cmd/internal/obj/arm64","cmd/internal/obj/riscv","cmd/internal/obj/riscv/testdata","cmd/internal/obj/riscv/testdata/testbranch","cmd/internal/obj/ppc64","cmd/internal/obj/s390x","cmd/internal/obj/arm","cmd/internal/gcprog","cmd/internal/sys","cmd/nm","cmd/doc","cmd/doc/testdata","cmd/doc/testdata/nested","cmd/doc/testdata/nested/nested","cmd/doc/testdata/nested/empty","cmd/doc/testdata/merge","archive","archive/zip","archive/zip/testdata","archive/tar","archive/tar/testdata","hash","hash/crc64","hash/fnv","hash/maphash","hash/crc32","hash/adler32","net","net/mail","net/rpc","net/rpc/jsonrpc","net/url","net/http","net/http/httptest","net/http/httptrace","net/http/cgi","net/http/cgi/testdata","net/http/httputil","net/http/testdata","net/http/pprof","net/http/cookiejar","net/http/internal","net/http/internal/ascii","net/http/internal/testcert","net/http/fcgi","net/smtp","net/testdata","net/textproto","net/internal","net/internal/socktest","bytes","database","database/sql","database/sql/driver","path","path/filepath","compress","compress/gzip","compress/gzip/testdata","compress/flate","compress/flate/testdata","compress/bzip2","compress/bzip2/testdata","compress/testdata","compress/lzw","compress/zlib","strings","sort","unsafe","crypto","crypto/sha512","crypto/hmac","crypto/aes","crypto/ed25519","crypto/ed25519/testdata","crypto/ed25519/internal","crypto/ed25519/internal/edwards25519","crypto/ed25519/internal/edwards25519/field","crypto/ed25519/internal/edwards25519/field/_asm","crypto/rc4","crypto/sha1","crypto/x509","crypto/x509/pkix","crypto/x509/testdata","crypto/x509/internal","crypto/x509/internal/macos","crypto/dsa","crypto/subtle","crypto/rsa","crypto/rsa/testdata","crypto/md5","crypto/cipher","crypto/sha256","crypto/elliptic","crypto/elliptic/internal","crypto/elliptic/internal/fiat","crypto/tls","crypto/tls/testdata","crypto/des","crypto/internal","crypto/internal/subtle","crypto/internal/randutil","crypto/rand","crypto/ecdsa","crypto/ecdsa/testdata","testdata","unicode","unicode/utf8","unicode/utf16","container","container/ring","container/heap","container/list","vendor","golang.org","golang.org/x","golang.org/x/text","golang.org/x/text/transform","golang.org/x/text/secure","golang.org/x/text/secure/bidirule","golang.org/x/text/unicode","golang.org/x/text/unicode/bidi","golang.org/x/text/unicode/norm","golang.org/x/net","golang.org/x/net/nettest","golang.org/x/net/dns","golang.org/x/net/dns/dnsmessage","golang.org/x/net/route","golang.org/x/net/http2","golang.org/x/net/http2/hpack","golang.org/x/net/http","golang.org/x/net/http/httpguts","golang.org/x/net/http/httpproxy","golang.org/x/net/lif","golang.org/x/net/idna","golang.org/x/crypto","golang.org/x/crypto/cryptobyte","golang.org/x/crypto/cryptobyte/asn1","golang.org/x/crypto/poly1305","golang.org/x/crypto/chacha20poly1305","golang.org/x/crypto/chacha20","golang.org/x/crypto/curve25519","golang.org/x/crypto/internal","golang.org/x/crypto/internal/subtle","golang.org/x/crypto/hkdf","golang.org/x/sys","golang.org/x/sys/cpu","internal","internal/cpu","internal/syscall","internal/syscall/windows","internal/syscall/windows/registry","internal/syscall/windows/sysdll","internal/syscall/unix","internal/syscall/execenv","internal/bytealg","internal/itoa","internal/abi","internal/abi/testdata","internal/obscuretestdata","internal/sysinfo","internal/buildcfg","internal/poll","internal/unsafeheader","internal/goversion","internal/oserror","internal/fmtsort","internal/race","internal/reflectlite","internal/testenv","internal/trace","internal/trace/testdata","internal/lazytemplate","internal/goexperiment","internal/lazyregexp","internal/goroot","internal/profile","internal/nettrace","internal/testlog","internal/cfg","internal/xcoff","internal/xcoff/testdata","internal/singleflight","internal/execabs","io","io/fs","io/ioutil","io/ioutil/testdata",
	}
)

// TODO: Consider optimizing by doing single loop over nodes and multiple filters per loop.

func contains(needle string, haystack []string) bool {
	for _,v := range haystack {
		if v == needle {
			return true
		}
	}
	return false
}

func RemoveIsolatedNodes(graph *callgraph.Graph) int {
	count := 0
	for _,node := range graph.Nodes {
		if len(node.Out) == 0 && len(node.In) == 0 {
			graph.DeleteNode(node)
			count++
		}
	}
	return count
}

func RemoveNodesBySuffix(graph *callgraph.Graph, suffix string) int {
	count := 0
	for _,node := range graph.Nodes {
		if strings.HasSuffix(node.Func.String(), suffix) {
			graph.DeleteNode(node)
			count++
		}
	}

	return count
}

func RemoveNodesByRegex(graph *callgraph.Graph, expr string) int {
	count := 0
	matcher := regexp.MustCompile(expr)
	for _,node := range graph.Nodes {
		if matcher.MatchString(node.Func.String()) {
			graph.DeleteNode(node)
			count++
		}
	}

	return count
}

func RemoveStdLib(graph *callgraph.Graph) int {
	count := 0
	for _,node := range graph.Nodes {
		if contains(node.Func.Pkg.Pkg.Path(), stdlib) {
			graph.DeleteNode(node)
			count++
		}
	}
	return count
}

func KeepEdgesByPackage(graph *callgraph.Graph, sourcePkg string, targetPkg string) int {
	count := 0
	toRemove := []*callgraph.Edge{} // Can't remove edges while visiting, store in a slice for removal later

	callgraph.GraphVisitEdges(graph, func(edge *callgraph.Edge) error {
		if strings.HasPrefix(edge.Caller.Func.Pkg.Pkg.Path(), sourcePkg) &&
			strings.HasPrefix(edge.Callee.Func.Pkg.Pkg.Path(), targetPkg) {
			return nil
		}
		count++
		toRemove = append(toRemove, edge)
		return nil
	})

	for _,edge := range toRemove {
		removeInEdge(edge)
		removeOutEdge(edge)
	}

	return count
}

// Copied from https://cs.opensource.google/go/x/tools/+/refs/tags/v0.1.5:go/callgraph/util.go;l=151-181
// removeOutEdge removes edge.Caller's outgoing edge 'edge'.
func removeOutEdge(edge *callgraph.Edge) {
	caller := edge.Caller
	n := len(caller.Out)
	for i, e := range caller.Out {
		if e == edge {
			// Replace it with the final element and shrink the slice.
			caller.Out[i] = caller.Out[n-1]
			caller.Out[n-1] = nil // aid GC
			caller.Out = caller.Out[:n-1]
			return
		}
	}
	panic("edge not found: " + edge.String())
}

// removeInEdge removes edge.Callee's incoming edge 'edge'.
func removeInEdge(edge *callgraph.Edge) {
	caller := edge.Callee
	n := len(caller.In)
	for i, e := range caller.In {
		if e == edge {
			// Replace it with the final element and shrink the slice.
			caller.In[i] = caller.In[n-1]
			caller.In[n-1] = nil // aid GC
			caller.In = caller.In[:n-1]
			return
		}
	}
	panic("edge not found: " + edge.String())
}
