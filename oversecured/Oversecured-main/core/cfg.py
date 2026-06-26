import logging
logger = logging.getLogger(__name__)

class BasicBlock:
    __slots__ = ('label', 'start_idx', 'end_idx', 'instructions', 'succs', 'preds', 'dominators')

    def __init__(self, label, start_idx, end_idx, instructions):
        self.label = label
        self.start_idx = start_idx
        self.end_idx = end_idx
        self.instructions = instructions
        self.succs = []
        self.preds = []
        self.dominators = set()

    def __repr__(self):
        return f"BB_{self.label}(ins:{self.start_idx}-{self.end_idx}, succ:{self.succs}, pred:{self.preds})"


BRANCH_OPCODES = {
    "if-eq", "if-ne", "if-lt", "if-ge", "if-gt", "if-le",
    "if-eqz", "if-nez", "if-ltz", "if-gez", "if-gtz", "if-lez",
    "if-eq-object", "if-ne-object",
}
RETURN_OPCODES = {"return-void", "return", "return-wide", "return-object"}
GOTO_OPCODES = {"goto", "goto/16", "goto/32"}
THROW_OPCODES = {"throw"}
SWITCH_OPCODES = {"packed-switch", "sparse-switch"}

ALL_BRANCHES = BRANCH_OPCODES | GOTO_OPCODES | RETURN_OPCODES | THROW_OPCODES | SWITCH_OPCODES


def get_jump_target(label_str):
    try:
        if label_str.startswith(":"):
            label_str = label_str[1:]
        if label_str.startswith("label_"):
            return int(label_str.split("_")[1])
        return int(label_str)
    except (ValueError, IndexError):
        return None


def parse_label_from_mnemonic(output, name):
    parts = output.split()
    if len(parts) >= 2:
        return get_jump_target(parts[-1])
    return None


class MethodCFG:
    def __init__(self, method, bytecode_instructions):
        self.method = method
        self.instructions = bytecode_instructions
        self.blocks = []
        self._build()

    def _build(self):
        if not self.instructions:
            return

        leaders = {0}
        n = len(self.instructions)

        for i, ins in enumerate(self.instructions):
            name = ins.get_name()
            if name in ALL_BRANCHES:
                if i + 1 < n:
                    leaders.add(i + 1)
                target = parse_label_from_mnemonic(ins.get_output(), name)
                if target is not None and target < n:
                    leaders.add(target)

        leaders = sorted(leaders)
        blocks = []
        for idx, start in enumerate(leaders):
            end = leaders[idx + 1] if idx + 1 < len(leaders) else n
            blk_ins = self.instructions[start:end]
            bb = BasicBlock(idx, start, end, blk_ins)
            blocks.append(bb)

        for i, bb in enumerate(blocks):
            last_ins = bb.instructions[-1]
            name = last_ins.get_name()

            if name in RETURN_OPCODES or name in THROW_OPCODES:
                pass
            elif name in GOTO_OPCODES:
                target = parse_label_from_mnemonic(last_ins.get_output(), name)
                if target is not None:
                    for j, other in enumerate(blocks):
                        if other.start_idx == target:
                            bb.succs.append(j)
                            other.preds.append(i)
                            break
            elif name in BRANCH_OPCODES:
                target = parse_label_from_mnemonic(last_ins.get_output(), name)
                if target is not None:
                    for j, other in enumerate(blocks):
                        if other.start_idx == target:
                            bb.succs.append(j)
                            other.preds.append(i)
                            break
                if i + 1 < len(blocks):
                    bb.succs.append(i + 1)
                    blocks[i + 1].preds.append(i)
            elif name in SWITCH_OPCODES:
                if i + 1 < len(blocks):
                    bb.succs.append(i + 1)
                    blocks[i + 1].preds.append(i)
                try:
                    for entry in last_ins.get_operands():
                        if hasattr(entry, 'values'):
                            for v in entry.values:
                                target = int(v)
                                for j, other in enumerate(blocks):
                                    if other.start_idx == target:
                                        bb.succs.append(j)
                                        other.preds.append(i)
                                        break
                except Exception:
                    logger.debug("Silent exception caught", exc_info=True)
            else:
                if i + 1 < len(blocks):
                    bb.succs.append(i + 1)
                    blocks[i + 1].preds.append(i)

        self.blocks = blocks

    def get_block_for_ins(self, ins_idx):
        for bb in self.blocks:
            if bb.start_idx <= ins_idx < bb.end_idx:
                return bb
        return None

    def enumerate_paths(self, start_ins, end_ins):
        start_bb = self.get_block_for_ins(start_ins)
        end_bb = self.get_block_for_ins(end_ins)
        if start_bb is None or end_bb is None:
            return []

        paths = []

        def dfs(current, visited, path_bbs):
            if current == end_bb.label:
                paths.append(list(path_bbs) + [current])
                return
            if current in visited:
                return
            visited.add(current)
            path_bbs.append(current)
            for succ in self.blocks[current].succs:
                dfs(succ, visited, path_bbs)
            path_bbs.pop()
            visited.discard(current)

        dfs(start_bb.label, set(), [])
        return paths

    def compute_dominators(self):
        for bb in self.blocks:
            bb.dominators = set(range(len(self.blocks)))
        entry = 0
        self.blocks[entry].dominators = {entry}

        changed = True
        while changed:
            changed = False
            for i in range(1, len(self.blocks)):
                if not self.blocks[i].preds:
                    continue
                new_dom = set(range(len(self.blocks)))
                for p in self.blocks[i].preds:
                    new_dom &= self.blocks[p].dominators
                new_dom.add(i)
                if new_dom != self.blocks[i].dominators:
                    self.blocks[i].dominators = new_dom
                    changed = True

    def to_mermaid(self, highlight_blocks=None, max_blocks=20):
        if not self.blocks:
            return "flowchart TD\n  START[No blocks]"
        if len(self.blocks) > max_blocks:
            return f"flowchart TD\n  TOO_MANY[CFG has {len(self.blocks)} blocks; max display is {max_blocks}]"
        highlight_blocks = highlight_blocks or set()
        lines = ["flowchart TD"]
        for bb in self.blocks:
            bid = f"BB{bb.label}"
            ins_summary = "; ".join(
                ins.get_name() for ins in bb.instructions[:3]
            )
            if len(bb.instructions) > 3:
                ins_summary += f" ... (+{len(bb.instructions)-3} more)"
            style = "fill:#e74c3c33,stroke:#e74c3c" if bb.label in highlight_blocks else "fill:#1e272e,stroke:#636e72"
            lines.append(f'  {bid}["{ins_summary}"]:::{["normal","highlight"][bb.label in highlight_blocks]}')
            lines.append(f'  class {bid} {"highlight" if bb.label in highlight_blocks else "normal"}')
        for bb in self.blocks:
            for s in bb.succs:
                lines.append(f"  BB{bb.label} --> BB{s}")
        lines.append("")
        lines.append('classDef normal fill:#1e272e,stroke:#636e72,color:#e6e9ed')
        lines.append('classDef highlight fill:#8e44ad33,stroke:#8e44ad,color:#fff')
        return "\n".join(lines)
