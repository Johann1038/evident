"""Cross-package static reachability for Python with explicit uncertainty (evidence L3b and L4).

The analysis builds one program graph over the application and the installed packages that lie
on dependency paths to a vulnerable package. Nodes are functions/methods and module bodies.

Edges are *strong* (resolved call: import-qualified call, constructor call, self-method in the
class hierarchy, typed local, container-dispatch over a literal container) or *weak*
(over-approximations: method-name matching restricted to imported packages, escaped function
references reached through unresolved dynamic calls, computed getattr over a module's exports,
string-encoded symbol references).

Verdicts for a set of vulnerable symbols:
  CONFIRMED  reachable from application roots through strong edges only
  POSSIBLE   reachable only when weak edges are admitted
  REFUTED    unreachable even with weak edges, and no reflection (eval/exec/computed import)
             was found in the reachable region that could load the vulnerable package
  UNKNOWN    no source / no symbol data / reflection may defeat the analysis
"""
from __future__ import annotations

import ast
import builtins
import re
from collections import defaultdict, deque
from dataclasses import dataclass, field
from pathlib import Path

TEST_RX = re.compile(r"(^|/)(tests?|testing|test_utils|docs?|examples?|benchmarks?)(/|$)|(^|/)(test_[^/]*|[^/]*_test|conftest)\.py$")
BUILTINS = set(dir(builtins))
_ITER = ("__iter__", "__next__")
PROTOCOL_BUILTINS = {
    "str": ("__str__", "__repr__"), "repr": ("__repr__",), "format": ("__format__", "__str__"),
    "print": ("__str__", "__repr__"), "len": ("__len__",), "bool": ("__bool__", "__len__"), "hash": ("__hash__",),
    "iter": _ITER, "next": ("__next__",), "list": _ITER, "tuple": _ITER, "set": _ITER, "sorted": _ITER,
    "sum": _ITER, "min": _ITER, "max": _ITER, "any": _ITER, "all": _ITER, "enumerate": _ITER, "zip": _ITER,
    "dict": _ITER, "frozenset": _ITER, "map": _ITER, "filter": _ITER, "reversed": ("__reversed__", "__len__", "__getitem__"),
    "int": ("__int__", "__index__"), "float": ("__float__",), "bytes": ("__bytes__",),
}
ENTRY_NAMES = {"main", "run", "cli", "app", "application", "handler", "lambda_handler", "create_app", "wsgi", "asgi"}


@dataclass
class Mod:
    qual: str
    path: Path
    pkg: str            # distribution name or "__app__"
    is_test: bool = False
    tree: ast.AST | None = None
    bindings: dict[str, str] = field(default_factory=dict)   # module-level name -> qualified target
    stars: list[str] = field(default_factory=list)
    containers: dict[str, set[str]] = field(default_factory=dict)


@dataclass
class Cls:
    qual: str
    bases: list[str]
    methods: set[str]


class Program:
    def __init__(self):
        self.mods: dict[str, Mod] = {}
        self.funcs: dict[str, str] = {}          # func qual -> module qual
        self.func_pkg: dict[str, str] = {}
        self.classes: dict[str, Cls] = {}
        self.methods_by_name: dict[str, set[str]] = defaultdict(set)
        self.strong: dict[str, set[str]] = defaultdict(set)
        self.weak: dict[str, set[str]] = defaultdict(set)
        self.escapes: dict[str, set[str]] = defaultdict(set)   # pkg -> escaped symbols
        self.dyncall: set[str] = set()
        self.reflect: dict[str, set[str]] = defaultdict(set)   # node -> kinds
        self.imports: dict[str, set[str]] = defaultdict(set)   # module -> imported modules
        self.roots: set[str] = set()
        self.pkg_roots: dict[str, set[str]] = {}               # dist -> top-level import names
        self.top_owner: dict[str, str] = {}                    # top-level import name -> dist
        self.app_suffix: dict[str, list[str]] = defaultdict(list)
        self.referenced: set[str] = set()
        self.decorated: set[str] = set()

    # ------------------------------------------------------------------ loading
    def add_tree(self, root: Path, pkg: str, *, app: bool = False, only_tops: set[str] | None = None) -> int:
        n = 0
        tops = set()
        files = []
        if only_tops is not None:
            for t in only_tops:
                if (root / t).is_dir():
                    files += sorted((root / t).rglob("*.py"))
                elif (root / f"{t}.py").exists():
                    files.append(root / f"{t}.py")
        else:
            files = sorted(root.rglob("*.py"))
        for f in files:
            rel = f.relative_to(root).as_posix()
            if "/." in "/" + rel or rel.startswith(("build/", "dist/")):
                continue
            parts = rel[:-3].split("/")
            if parts[-1] == "__init__":
                parts = parts[:-1]
            if not parts or any(not p.isidentifier() for p in parts):
                if app and parts and all(p.replace("-", "_").isidentifier() for p in parts):
                    parts = [p.replace("-", "_") for p in parts]
                else:
                    continue
            qual = ".".join(parts)
            if pkg != "__app__":
                if qual in self.mods:
                    continue
            else:
                qual = "__app__." + qual
            m = Mod(qual, f, pkg, is_test=bool(app and TEST_RX.search(rel)))
            self.mods[qual] = m
            if app:
                segs = qual.split(".")[1:]
                for i in range(len(segs)):
                    self.app_suffix[".".join(segs[i:])].append(qual)
            else:
                tops.add(parts[0])
            n += 1
        if not app:
            self.pkg_roots[pkg] = tops
            for t in tops:
                self.top_owner.setdefault(t, pkg)
        return n

    def build(self) -> None:
        for m in list(self.mods.values()):
            try:
                src = m.path.read_text("utf8", errors="replace")
                m.tree = ast.parse(src)
            except (SyntaxError, ValueError, RecursionError):
                m.tree = None
                continue
            _Collector(self, m).collect()
        for m in self.mods.values():
            if m.tree is not None:
                _Linker(self, m).link()
                m.tree = None   # free memory
        self._roots()

    def _roots(self) -> None:
        for q, m in self.mods.items():
            if m.pkg == "__app__" and not m.is_test:
                self.roots.add(q + ".<module>")
        for f, mq in self.funcs.items():
            m = self.mods[mq]
            if m.pkg != "__app__" or m.is_test:
                continue
            name = f.rsplit(".", 1)[-1]
            cls = f.rsplit(".", 1)[0]
            if (f in self.decorated or f in self.referenced or name in ENTRY_NAMES
                    or (cls in self.classes and cls in self.referenced)):
                self.roots.add(f)

    # ------------------------------------------------------------------ resolution
    def module_of_import(self, name: str, cur: Mod | None = None) -> str | None:
        """Resolve an absolute dotted import name to a known module qual (app or package)."""
        if name in self.mods and not name.startswith("__app__"):
            return name
        top = name.split(".")[0]
        if top in self.top_owner:
            # deepest existing module prefix
            parts = name.split(".")
            for i in range(len(parts), 0, -1):
                cand = ".".join(parts[:i])
                if cand in self.mods:
                    return cand
            return None
        cands = self.app_suffix.get(name)
        if cands:
            if cur is not None and cur.pkg == "__app__":
                cands = sorted(cands, key=lambda c: (-_common(c, cur.qual), len(c)))
            else:
                cands = sorted(cands, key=len)
            return cands[0]
        return None

    def resolve(self, dotted: str, depth: int = 0) -> str | None:
        """Canonicalise a dotted symbol (following re-exports) to a module/class/function qual."""
        if depth > 12 or not dotted:
            return None
        if dotted in self.funcs or dotted in self.classes or dotted in self.mods:
            return dotted
        parts = dotted.split(".")
        for i in range(len(parts) - 1, 0, -1):
            head = ".".join(parts[:i])
            rest = parts[i:]
            if head in self.mods:
                m = self.mods[head]
                b = m.bindings.get(rest[0])
                if b is None:
                    sub = head + "." + rest[0]
                    if sub in self.mods:
                        return self.resolve(".".join([sub] + rest[1:]), depth + 1)
                    for s in m.stars:
                        r = self.resolve(".".join([s] + rest), depth + 1)
                        if r:
                            return r
                    return None
                if b == dotted:
                    return None
                return self.resolve(".".join([b] + rest[1:]), depth + 1)
            if head in self.classes and len(rest) == 1:
                return self.lookup_method(head, rest[0])
        return None

    def lookup_method(self, cls: str, name: str, seen=None) -> str | None:
        seen = seen or set()
        if cls in seen or cls not in self.classes:
            return None
        seen.add(cls)
        c = self.classes[cls]
        if name in c.methods:
            return f"{cls}.{name}"
        for b in c.bases:
            r = self.lookup_method(b, name, seen)
            if r:
                return r
        return None

    def subclasses_methods(self, cls: str, name: str) -> set[str]:
        out = set()
        for q, c in self.classes.items():
            if cls in c.bases and name in c.methods:
                out.add(f"{q}.{name}")
        return out

    def exports(self, modq: str) -> set[str]:
        m = self.mods.get(modq)
        if not m:
            return set()
        out = {f for f, mq in self.funcs.items() if mq == modq and f.count(".") == modq.count(".") + 1}
        for b in m.bindings.values():
            r = self.resolve(b)
            if r and (r in self.funcs or r in self.classes):
                out.add(r)
        return out

    def pkg_of(self, node: str) -> str | None:
        q = node[:-9] if node.endswith(".<module>") else node
        if q in self.funcs:
            return self.func_pkg.get(q)
        if q in self.mods:
            return self.mods[q].pkg
        if q in self.classes:
            return self.mods[q.rsplit(".", 1)[0]].pkg if q.rsplit(".", 1)[0] in self.mods else None
        return None

    # ------------------------------------------------------------------ queries
    def reach(self, weak: bool) -> dict[str, str | None]:
        """BFS from roots; returns {node: parent}."""
        par: dict[str, str | None] = {r: None for r in self.roots}
        dq = deque(self.roots)
        while dq:
            u = dq.popleft()
            nxt = set(self.strong.get(u, ()))
            if weak:
                nxt |= self.weak.get(u, set())
                if u in self.dyncall:
                    p = self.pkg_of(u)
                    if p:
                        nxt |= self.escapes.get(p, set())
            for v in nxt:
                v2 = v
                if v2 in self.classes:
                    for meth in ("__init__", "__new__", "__call__"):
                        r = self.lookup_method(v2, meth)
                        if r and r not in par:
                            par[r] = u
                            dq.append(r)
                    continue
                if v2 in self.mods:
                    v2 = v2 + ".<module>"
                if v2 not in par:
                    par[v2] = u
                    dq.append(v2)
        return par

    def imported_pkgs(self) -> tuple[set[str], set[str]]:
        """(packages whose modules are transitively imported by non-test app code, reflective pkgs)."""
        seen = set()
        dq = deque(q for q, m in self.mods.items() if m.pkg == "__app__" and not m.is_test)
        seen |= set(dq)
        while dq:
            u = dq.popleft()
            for v in self.imports.get(u, ()):
                if v not in seen:
                    seen.add(v)
                    dq.append(v)
        pk = {self.mods[q].pkg for q in seen if q in self.mods}
        refl = set()
        for node, kinds in self.reflect.items():
            if kinds & {"import_module", "__import__", "exec", "eval"}:
                p = self.pkg_of(node)
                mq = node[:-9] if node.endswith(".<module>") else self.funcs.get(node)
                if p and mq in seen:
                    refl.add(p)
        return pk, refl


def _common(a: str, b: str) -> int:
    n = 0
    for x, y in zip(a.split("."), b.split(".")):
        if x != y:
            break
        n += 1
    return n


class _Collector(ast.NodeVisitor):
    """Pass 1: definitions, module-level bindings, star imports, literal containers."""

    def __init__(self, prog: Program, mod: Mod):
        self.p, self.m = prog, mod
        self.stack: list[str] = []

    def collect(self):
        self.visit(self.m.tree)

    def _q(self, name):
        return ".".join([self.m.qual] + self.stack + [name])

    def _abs(self, node: ast.ImportFrom) -> str:
        if node.level == 0:
            return node.module or ""
        base = self.m.qual.split(".")
        is_pkg = self.m.path.name == "__init__.py"
        cut = node.level - (1 if is_pkg else 0)
        base = base[: len(base) - cut] if cut > 0 else base
        if self.m.pkg == "__app__":
            base = base[1:]
        return ".".join(base + ([node.module] if node.module else []))

    def visit_Import(self, node):
        if not self.stack:
            for a in node.names:
                if a.asname:
                    self.m.bindings[a.asname] = a.name
                else:
                    top = a.name.split(".")[0]
                    self.m.bindings.setdefault(top, top)

    def visit_ImportFrom(self, node):
        if self.stack:
            return
        base = self._abs(node)
        for a in node.names:
            if a.name == "*":
                self.m.stars.append(base)
            else:
                self.m.bindings[a.asname or a.name] = f"{base}.{a.name}" if base else a.name

    def visit_FunctionDef(self, node):
        q = self._q(node.name)
        self.p.funcs[q] = self.m.qual
        self.p.func_pkg[q] = self.m.pkg
        if node.decorator_list:
            self.p.decorated.add(q)
        if self.stack and ".".join([self.m.qual] + self.stack) in self.p.classes:
            self.p.classes[".".join([self.m.qual] + self.stack)].methods.add(node.name)
            self.p.methods_by_name[node.name].add(q)
        if not self.stack:
            self.m.bindings[node.name] = q
        self.stack.append(node.name)
        self.generic_visit(node)
        self.stack.pop()

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_ClassDef(self, node):
        q = self._q(node.name)
        bases = [_dotted(b) for b in node.bases]
        self.p.classes[q] = Cls(q, [b for b in bases if b], set())
        if not self.stack:
            self.m.bindings[node.name] = q
        self.stack.append(node.name)
        self.generic_visit(node)
        self.stack.pop()

    def visit_Assign(self, node):
        if not self.stack and isinstance(node.value, (ast.Dict, ast.List, ast.Tuple, ast.Set)):
            elts = node.value.values if isinstance(node.value, ast.Dict) else node.value.elts
            refs = {_dotted(e) for e in elts}
            refs.discard(None)
            for t in node.targets:
                if isinstance(t, ast.Name) and refs:
                    self.m.containers[t.id] = refs
        if not self.stack:
            d = _dotted(node.value)
            for t in node.targets:
                if isinstance(t, ast.Name) and d:
                    self.m.bindings.setdefault(t.id, "@" + d)  # alias to be resolved in linker
        self.generic_visit(node)


def _dotted(n) -> str | None:
    if isinstance(n, ast.Name):
        return n.id
    if isinstance(n, ast.Attribute):
        b = _dotted(n.value)
        return f"{b}.{n.attr}" if b else None
    return None


class _Linker(ast.NodeVisitor):
    """Pass 2: references and calls inside each function / module body."""

    def __init__(self, prog: Program, mod: Mod):
        self.p, self.m = prog, mod
        self.stack: list[str] = []
        self.node_stack: list[str] = [mod.qual + ".<module>"]
        self.cls_stack: list[str] = []
        self.local: list[dict[str, str]] = [{}]
        self.call_funcs: set[int] = set()
        # canonicalise module-level aliases '@x.y'
        for k, v in list(mod.bindings.items()):
            if v.startswith("@"):
                mod.bindings[k] = self._qualify(v[1:], top=True) or v[1:]

    def link(self):
        self.visit(self.m.tree)

    @property
    def cur(self):
        return self.node_stack[-1]

    # -- helpers
    def _qualify(self, dotted: str, top: bool = False) -> str | None:
        head, _, rest = dotted.partition(".")
        tgt = None
        if not top:
            for scope in reversed(self.local):
                if head in scope:
                    tgt = scope[head]
                    break
        if tgt is None:
            b = self.m.bindings.get(head)
            if b is not None and not b.startswith("@"):
                tgt = b
        if tgt is None:
            return None
        full = tgt + ("." + rest if rest else "")
        if self.m.pkg == "__app__" or full.split(".")[0] not in self.p.top_owner:
            first = full.split(".")[0]
            if first not in self.p.top_owner and not full.startswith("__app__"):
                modq = self._app_module_prefix(full)
                if modq:
                    return modq
        return full

    def _app_module_prefix(self, full: str) -> str | None:
        parts = full.split(".")
        for i in range(len(parts), 0, -1):
            mq = self.p.module_of_import(".".join(parts[:i]), self.m)
            if mq and mq.startswith("__app__"):
                return ".".join([mq] + parts[i:])
        return None

    def _edge(self, tgt: str | None, strong: bool = True):
        if not tgt:
            return
        r = self.p.resolve(tgt)
        if r is None:
            return
        (self.p.strong if strong else self.p.weak)[self.cur].add(r)

    def _import(self, name: str):
        mq = self.p.module_of_import(name, self.m)
        if mq:
            self.p.imports[self.m.qual].add(mq)
            # importing 'a.b.c' executes a, a.b, a.b.c bodies
            parts = mq.split(".")
            for i in range(1, len(parts) + 1):
                q = ".".join(parts[:i])
                if q in self.p.mods:
                    self.p.strong[self.cur].add(q)
                    self.p.imports[self.m.qual].add(q)

    # -- imports
    def visit_Import(self, node):
        for a in node.names:
            self._import(a.name)
            if self.stack:
                if a.asname:
                    self.local[-1][a.asname] = a.name
                else:
                    self.local[-1][a.name.split(".")[0]] = a.name.split(".")[0]

    def visit_ImportFrom(self, node):
        base = _Collector(self.p, self.m)._abs(node)
        self._import(base)
        for a in node.names:
            if a.name != "*":
                sub = f"{base}.{a.name}"
                if self.p.module_of_import(sub, self.m) and (sub in self.p.mods or sub in self.p.app_suffix):
                    self._import(sub)
                if self.stack:
                    self.local[-1][a.asname or a.name] = sub

    # -- definitions
    def visit_FunctionDef(self, node):
        for d in node.decorator_list:
            self.visit(d)
        for dflt in node.args.defaults + node.args.kw_defaults:
            if dflt is not None:
                self.visit(dflt)
        q = ".".join([self.m.qual] + self.stack + [node.name])
        self.stack.append(node.name)
        self.node_stack.append(q)
        self.local.append({})
        for st in node.body:
            self.visit(st)
        self.local.pop()
        self.node_stack.pop()
        self.stack.pop()

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_Lambda(self, node):
        self.visit(node.body)

    def visit_ClassDef(self, node):
        for b in node.bases:
            self.visit(b)
        for d in node.decorator_list:
            self.visit(d)
        q = ".".join([self.m.qual] + self.stack + [node.name])
        c = self.p.classes.get(q)
        if c:
            c.bases = [self.p.resolve(self._qualify(b) or b) or b for b in c.bases]
        self.stack.append(node.name)
        self.cls_stack.append(q)
        for st in node.body:
            self.visit(st)
        self.cls_stack.pop()
        self.stack.pop()

    # -- local typing / aliasing
    def visit_Assign(self, node):
        self.visit(node.value)
        d = _dotted(node.value)
        typ = None
        if isinstance(node.value, ast.Call):
            fd = _dotted(node.value.func)
            if fd:
                r = self.p.resolve(self._qualify(fd) or "")
                if r in self.p.classes:
                    typ = "#" + r
        for t in node.targets:
            if isinstance(t, ast.Name) and len(self.local) > 1:
                if typ:
                    self.local[-1][t.id] = typ
                elif d:
                    q = self._qualify(d)
                    if q:
                        self.local[-1][t.id] = q
            else:
                self.visit(t)

    # -- references and calls
    def visit_Call(self, node):
        f = node.func
        handled = False
        fd = _dotted(f)
        if isinstance(f, ast.Name) and f.id == "getattr" and len(node.args) >= 2:
            base = _dotted(node.args[0])
            bq = self._qualify(base) if base else None
            if isinstance(node.args[1], ast.Constant) and isinstance(node.args[1].value, str):
                if bq:
                    self._edge(f"{bq}.{node.args[1].value}")
            else:
                self.p.reflect[self.cur].add("getattr")
                if base == "self" and self.cls_stack:
                    # computed method dispatch on self: any method of the class hierarchy
                    todo, seen = [self.cls_stack[-1]], set()
                    while todo:
                        c = todo.pop()
                        if c in seen or c not in self.p.classes:
                            continue
                        seen.add(c)
                        for mm in self.p.classes[c].methods:
                            self.p.weak[self.cur].add(f"{c}.{mm}")
                        todo += self.p.classes[c].bases
                elif bq:
                    r = self.p.resolve(bq)
                    targets = self.p.exports(r) if r in self.p.mods else set()
                    if r in self.p.classes:
                        targets = {f"{r}.{mm}" for mm in self.p.classes[r].methods}
                    for t in targets:
                        self.p.weak[self.cur].add(t)
            handled = True
        elif isinstance(f, ast.Name) and f.id in ("eval", "exec"):
            self.p.reflect[self.cur].add(f.id)
        elif fd in ("importlib.import_module", "import_module", "__import__"):
            a0 = node.args[0] if node.args else None
            if isinstance(a0, ast.Constant) and isinstance(a0.value, str):
                self._import(a0.value)
            else:
                self.p.reflect[self.cur].add("import_module" if fd != "__import__" else "__import__")
            handled = True
        if isinstance(f, ast.Name) and f.id in PROTOCOL_BUILTINS:
            self._protocol(*PROTOCOL_BUILTINS[f.id])
        if not handled:
            if fd:
                self._call_dotted(fd)
            elif isinstance(f, ast.Subscript):
                cname = _dotted(f.value)
                cont = self.m.containers.get(cname) if cname else None
                if cont:
                    for ref in cont:
                        self._edge(self._qualify(ref) or ref)
                else:
                    self.p.dyncall.add(self.cur)
                self.visit(f.value)
                self.visit(f.slice)
            elif isinstance(f, ast.Attribute):
                inner = f.value
                if isinstance(inner, ast.Call) and _dotted(inner.func) and _dotted(inner.func).endswith(".get"):
                    cname = _dotted(inner.func)[:-4]
                    cont = self.m.containers.get(cname)
                    if cont:
                        for ref in cont:
                            self._edge(self._qualify(ref) or ref)
                self.visit(f.value)
                self._weak_method(f.attr)
            else:
                self.p.dyncall.add(self.cur)
                self.visit(f)
        for a in node.args:
            self._ref_arg(a)
        for k in node.keywords:
            self._ref_arg(k.value)

    def _ref_arg(self, a):
        d = _dotted(a)
        if d:
            q = self._qualify(d)
            r = self.p.resolve(q) if q else None
            if r and (r in self.p.funcs or r in self.p.classes):
                self.p.escapes[self.m.pkg].add(r)
                self.p.referenced.add(r)
                self.p.weak[self.cur].add(r)
                return
        self.visit(a)

    def _call_dotted(self, fd: str):
        head, _, rest = fd.partition(".")
        if head == "self" and self.cls_stack and rest and "." not in rest:
            cls = self.cls_stack[-1]
            r = self.p.lookup_method(cls, rest)
            if r:
                self.p.strong[self.cur].add(r)
            for s in self.p.subclasses_methods(cls, rest):
                self.p.weak[self.cur].add(s)
            if not r:
                self._weak_method(rest)
            return
        if head == "super" or head == "cls":
            self._weak_method(fd.rsplit(".", 1)[-1])
            return
        loc = None
        for scope in reversed(self.local):
            if head in scope:
                loc = scope[head]
                break
        if loc and loc.startswith("#"):
            cls = loc[1:]
            if rest and "." not in rest:
                r = self.p.lookup_method(cls, rest)
                if r:
                    self.p.strong[self.cur].add(r)
                    return
            self._weak_method(fd.rsplit(".", 1)[-1])
            return
        q = self._qualify(fd)
        if q:
            r = self.p.resolve(q)
            if r:
                self.p.strong[self.cur].add(r)
                self.p.referenced.add(r)
                return
        if head in self.m.containers and not rest:
            return
        if "." in fd:
            self._weak_method(fd.rsplit(".", 1)[-1])
        elif head not in BUILTINS:
            self.p.dyncall.add(self.cur)

    def _protocol(self, *dunders: str):
        """Implicit protocol calls (str(), iteration, f-strings, len(), subscripts, with, in)."""
        for d in dunders:
            self._weak_method(d, allow_dunder=True)

    def visit_JoinedStr(self, node):
        self._protocol("__str__", "__format__")
        self.generic_visit(node)

    def visit_For(self, node):
        self._protocol("__iter__", "__next__")
        self.generic_visit(node)

    visit_AsyncFor = visit_For

    def visit_comprehension(self, node):
        self._protocol("__iter__", "__next__")
        self.generic_visit(node)

    def visit_Subscript(self, node):
        self._protocol("__getitem__")
        self.generic_visit(node)

    def visit_With(self, node):
        self._protocol("__enter__", "__exit__")
        self.generic_visit(node)

    visit_AsyncWith = visit_With

    def visit_Compare(self, node):
        if any(isinstance(o, (ast.In, ast.NotIn)) for o in node.ops):
            self._protocol("__contains__")
        if any(isinstance(o, (ast.Eq, ast.NotEq)) for o in node.ops):
            self._protocol("__eq__")
        self.generic_visit(node)

    def _weak_method(self, name: str, allow_dunder: bool = False):
        if name.startswith("__") and name not in ("__call__",) and not allow_dunder:
            return
        cands = self.p.methods_by_name.get(name, ())
        if not cands:
            return
        allowed = {self.m.pkg} | {self.p.mods[i].pkg for i in self.p.imports.get(self.m.qual, ()) if i in self.p.mods}
        for c in cands:
            if self.p.func_pkg.get(c) in allowed:
                self.p.weak[self.cur].add(c)

    def visit_Name(self, node):
        if isinstance(node.ctx, ast.Load):
            q = self._qualify(node.id)
            r = self.p.resolve(q) if q else None
            if r and (r in self.p.funcs or r in self.p.classes):
                self.p.referenced.add(r)
                self.p.escapes[self.m.pkg].add(r)
                self.p.weak[self.cur].add(r)

    def visit_Attribute(self, node):
        d = _dotted(node)
        if d and isinstance(node.ctx, ast.Load):
            q = self._qualify(d)
            r = self.p.resolve(q) if q else None
            if r:
                if r in self.p.funcs or r in self.p.classes:
                    self.p.referenced.add(r)
                    self.p.escapes[self.m.pkg].add(r)
                    self.p.weak[self.cur].add(r)
                return
        self.generic_visit(node)

    def visit_Constant(self, node):
        v = node.value
        if isinstance(v, str) and 3 < len(v) < 200 and re.fullmatch(r"[A-Za-z_][\w]*(\.[A-Za-z_]\w*)+", v):
            mq = self.p.module_of_import(v, self.m)
            if mq and (mq == v or mq.endswith("." + v) or v in self.p.mods):
                self._import(v)
            else:
                mod, _, attr = v.rpartition(".")
                mq = self.p.module_of_import(mod, self.m)
                if mq:
                    self._import(mod)
                    r = self.p.resolve(f"{mq}.{attr}")
                    if r:
                        self.p.weak[self.cur].add(r)
                        self.p.referenced.add(r)


# ---------------------------------------------------------------------- verdicts
@dataclass
class ReachResult:
    verdict: str            # CONFIRMED | POSSIBLE | REFUTED | UNKNOWN
    witness: list[str]
    reason: str


def path_to(par: dict, node: str) -> list[str]:
    out = [node]
    while par.get(out[-1]) is not None and len(out) < 40:
        out.append(par[out[-1]])
    return list(reversed(out))


class Analysis:
    """Holds both reachability closures for repeated symbol queries."""

    def __init__(self, prog: Program):
        self.p = prog
        self.strong = prog.reach(weak=False)
        self.weak = prog.reach(weak=True)
        self.imported, self.reflective = prog.imported_pkgs()

    def import_evidence(self, dist: str) -> str:
        if dist not in self.p.pkg_roots:
            return "UNKNOWN"
        if dist in self.imported:
            return "CONFIRMED"
        if self.reflective & ({"__app__"} | self.imported):
            return "UNKNOWN"
        return "REFUTED"

    def symbol_evidence(self, dist: str, symbols: list[str]) -> ReachResult:
        if dist not in self.p.pkg_roots:
            return ReachResult("UNKNOWN", [], "package source unavailable")
        nodes = []
        for s in symbols:
            r = self.p.resolve(s)
            if r is None and s.endswith(".<module>") and s[:-9] in self.p.mods:
                r = s
            if r in self.p.mods:
                r = r + ".<module>"
            if r:
                nodes.append(r)
        if not nodes:
            return ReachResult("UNKNOWN", [], "vulnerable symbols not found in installed source")
        for n in nodes:
            if n in self.strong:
                return ReachResult("CONFIRMED", path_to(self.strong, n), "strong call path")
        for n in nodes:
            if n in self.weak:
                return ReachResult("POSSIBLE", path_to(self.weak, n), "path requires over-approximated edges")
        if self.reflective & ({"__app__", dist} | self.imported):
            return ReachResult("UNKNOWN", [], "reflection in reachable region")
        return ReachResult("REFUTED", [], "no path even with over-approximation")


def analyse(app_dir: Path, pkg_dirs: dict[str, Path]) -> Analysis:
    prog = Program()
    for dist, d in pkg_dirs.items():
        if d is not None:
            prog.add_tree(d, dist)
    prog.add_tree(app_dir, "__app__", app=True)
    prog.build()
    return Analysis(prog)
