import logging
logger = logging.getLogger(__name__)

class ReachingDefinitions:
    """Reaching definitions analysis on a CFG."""

    def __init__(self, cfg):
        self.cfg = cfg
        self.gen = {}
        self.kill = {}
        self.in_ = {}
        self.out_ = {}
        self._analyze()

    def _analyze(self):
        n = len(self.cfg.blocks)
        all_defs = []
        def_to_block = {}

        for bi, bb in enumerate(self.cfg.blocks):
            for ins_idx in range(bb.start_idx, bb.end_idx):
                ud = self._get_def(ins_idx)
                if ud:
                    all_defs.append((ins_idx, ud))
                    def_to_block[ins_idx] = bi

        for bi, bb in enumerate(self.cfg.blocks):
            self.gen[bi] = set()
            self.kill[bi] = set()
            seen_regs = set()
            for ins_idx, (ins, reg) in [(i, d) for i, d in all_defs if def_to_block[i] == bi]:
                if reg not in seen_regs:
                    self.gen[bi].add(ins_idx)
                    seen_regs.add(reg)
            for ins_idx, (ins, reg) in all_defs:
                if ins_idx not in self.gen.get(bi, set()) and reg in [r for ii, (i, r) in all_defs if ii in self.gen.get(bi, set())]:
                    self.kill[bi].add(ins_idx)

        for bi in range(n):
            self.in_[bi] = set()
            self.out_[bi] = self.gen.get(bi, set()).copy()

        changed = True
        while changed:
            changed = False
            for bi in range(n):
                new_in = set()
                for p in self.cfg.blocks[bi].preds:
                    new_in |= self.out_.get(p, set())
                old_in = self.in_.get(bi, set())
                if new_in != old_in:
                    self.in_[bi] = new_in
                    changed = True

                old_out = self.out_.get(bi, set())
                new_out = self.gen.get(bi, set()) | (new_in - self.kill.get(bi, set()))
                if new_out != old_out:
                    self.out_[bi] = new_out
                    changed = True

    def _get_def(self, ins_idx):
        try:
            ins = self.cfg.instructions[ins_idx]
            name = ins.get_name()
            output = ins.get_output()
            parts = output.replace(",", "").split()
            if not parts:
                return None
            if name.startswith("move") or name.startswith("const"):
                return (ins, parts[0])
            if name.startswith("invoke"):
                return None
            if name in ("aget", "aget-object", "aget-wide"):
                return (ins, parts[0])
            if name in ("iget", "iget-object", "iget-wide"):
                return (ins, parts[0])
            if name in ("sget", "sget-object", "sget-wide"):
                return (ins, parts[0])
            if name == "new-instance":
                return (ins, parts[-1])
            if name in ("check-cast", "instance-of"):
                return (ins, parts[0])
            if name in ("array-length",):
                return (ins, parts[0])
            if name in ("neg-int", "not-int", "neg-long", "not-long", "neg-float", "neg-double"):
                return (ins, parts[0])
        except Exception:
            logger.debug("Silent exception caught", exc_info=True)
        return None


class LivenessAnalysis:
    """Live variable analysis on a CFG."""

    def __init__(self, cfg):
        self.cfg = cfg
        self.gen = {}
        self.kill = {}
        self.in_ = {}
        self.out_ = {}
        self._analyze()

    def _analyze(self):
        n = len(self.cfg.blocks)

        for bi, bb in enumerate(self.cfg.blocks):
            gen_set = set()
            kill_set = set()
            for ins_idx in range(bb.start_idx, bb.end_idx):
                used = self._get_uses(ins_idx)
                defined = self._get_defined(ins_idx)
                for u in used:
                    if u not in kill_set:
                        gen_set.add(u)
                for d in defined:
                    kill_set.add(d)

            self.gen[bi] = gen_set
            self.kill[bi] = kill_set
            self.in_[bi] = set()
            self.out_[bi] = set()

        changed = True
        while changed:
            changed = False
            for bi in range(n - 1, -1, -1):
                new_out = set()
                for s in self.cfg.blocks[bi].succs:
                    new_out |= self.in_.get(s, set())

                if new_out != self.out_.get(bi, set()):
                    self.out_[bi] = new_out
                    changed = True

                new_in = self.gen.get(bi, set()) | (new_out - self.kill.get(bi, set()))
                if new_in != self.in_.get(bi, set()):
                    self.in_[bi] = new_in
                    changed = True

    def _get_uses(self, ins_idx):
        used = set()
        try:
            ins = self.cfg.instructions[ins_idx]
            name = ins.get_name()
            output = ins.get_output()
            parts = output.replace(",", "").split()

            if name.startswith("invoke"):
                for p in parts:
                    if p and p[0].isalpha() or (p and p[0] == 'v'):
                        if p not in ('invoke-virtual', 'invoke-direct', 'invoke-static', 'invoke-interface', 'invoke-super', 'invoke-virtual/range', 'invoke-direct/range', 'invoke-static/range'):
                            if p.startswith('v') or p.startswith('p'):
                                used.add(p)
            elif name.startswith("move"):
                if len(parts) >= 2:
                    used.add(parts[-1])
            elif name in ("if-eq", "if-ne", "if-lt", "if-ge", "if-gt", "if-le",
                          "if-eq-object", "if-ne-object"):
                if len(parts) >= 2:
                    used.add(parts[-2])
                    used.add(parts[-1])
            elif name in ("if-eqz", "if-nez", "if-ltz", "if-gez", "if-gtz", "if-lez"):
                if len(parts) >= 1:
                    used.add(parts[-1])
            elif name in ("aget", "aget-object", "aget-wide"):
                if len(parts) >= 3:
                    used.add(parts[1])
                    used.add(parts[2])
            elif name in ("aput", "aput-object", "aput-wide"):
                if len(parts) >= 3:
                    used.add(parts[0])
                    used.add(parts[1])
                    used.add(parts[2])
            elif name in ("iput", "iput-object", "iput-wide"):
                if len(parts) >= 3:
                    used.add(parts[0])
                    used.add(parts[1])
            elif name in ("iget", "iget-object", "iget-wide"):
                if len(parts) >= 2:
                    used.add(parts[1])
            elif name in ("neg-int", "not-int", "neg-long", "not-long", "neg-float", "neg-double"):
                if len(parts) >= 2:
                    used.add(parts[-1])
        except Exception:
            logger.debug("Silent exception caught", exc_info=True)
        return used

    def _get_defined(self, ins_idx):
        defined = set()
        try:
            ins = self.cfg.instructions[ins_idx]
            name = ins.get_name()
            output = ins.get_output()
            parts = output.replace(",", "").split()
            if not parts:
                return defined
            if name.startswith("move") or name.startswith("const"):
                defined.add(parts[0])
            elif name in ("aget", "aget-object", "aget-wide", "iget", "iget-object", "iget-wide",
                          "sget", "sget-object", "sget-wide"):
                defined.add(parts[0])
            elif name == "new-instance":
                defined.add(parts[-1])
            elif name in ("check-cast", "instance-of", "array-length"):
                defined.add(parts[0])
            elif name.startswith("neg-") or name.startswith("not-"):
                defined.add(parts[0])
        except Exception:
            logger.debug("Silent exception caught", exc_info=True)
        return defined


class ConstantPropagation:
    """Tracks constant values through register assignments within a method."""

    def __init__(self, instructions):
        self.instructions = instructions
        self.constants = {}
        self._propagate()

    def _propagate(self):
        for idx, ins in enumerate(self.instructions):
            try:
                name = ins.get_name()
                output = ins.get_output()
                parts = output.replace(",", "").split()
                if not parts:
                    continue

                if name in ("const", "const/4", "const/16", "const-wide/16",
                            "const-wide/32", "const-wide", "const/high16", "const-wide/high16"):
                    if len(parts) >= 2:
                        val = parts[-1]
                        self.constants[parts[0]] = ("int", val)

                elif name in ("const-string", "const-string/jumbo"):
                    rest = output[output.find(parts[0]) + len(parts[0]):].strip()
                    if rest.startswith('"') and rest.endswith('"'):
                        val = rest[1:-1]
                        self.constants[parts[0]] = ("string", val)
                    elif len(parts) >= 2:
                        self.constants[parts[0]] = ("string", parts[-1])

                elif name == "const-class":
                    if len(parts) >= 2:
                        self.constants[parts[0]] = ("class", parts[-1])

                elif name.startswith("move"):
                    if len(parts) >= 2:
                        src = parts[-1]
                        if src in self.constants:
                            self.constants[parts[0]] = self.constants[src]
                        elif parts[0] in self.constants:
                            del self.constants[parts[0]]

            except Exception:
                logger.debug("Silent exception caught", exc_info=True)

    def get_constant(self, reg):
        return self.constants.get(reg)

    def get_all_constants(self):
        return dict(self.constants)
