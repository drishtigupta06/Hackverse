"""ReproductionBundle -- exploit reproduction bundle infrastructure."""


class ExploitStep:
    def __init__(self, action, details=None):
        self.action = action
        self.details = details or {}

    def to_dict(self):
        return {"action": self.action, **self.details}


class ReproductionBundle:
    def __init__(self, chain_id, component, component_type, package,
                 steps=None, system_context=None, device_profile=None,
                 score=50):
        self.chain_id = chain_id
        self.component = component
        self.component_type = component_type
        self.package = package
        self.steps = steps or []
        self.system_context = system_context or {}
        self.device_profile = device_profile
        self._score = score

    def to_dict(self):
        return {
            "chain_id": self.chain_id,
            "component": self.component,
            "component_type": self.component_type,
            "package": self.package,
            "steps": [s.to_dict() if hasattr(s, "to_dict") else s for s in self.steps],
            "system_context": self.system_context,
            "score": self._score,
        }


class BundleGenerator:
    def from_path(self, path, system_context=None, device_profile=None, chain_id=None):
        component = path.get("component", "unknown")
        comp_type = path.get("component_type", "unknown")
        steps = [ExploitStep(s.get("action", ""), s) for s in path.get("steps", [])]
        score = 50

        if device_profile and hasattr(device_profile, "sdk"):
            score = 60

        return ReproductionBundle(
            chain_id=chain_id or component,
            component=component,
            component_type=comp_type,
            package=system_context.get("package", "") if system_context else "",
            steps=steps,
            system_context=system_context,
            device_profile=device_profile,
            score=score,
        )


class BundleScorer:
    def score_all(self, bundles):
        for b in bundles:
            self._score_one(b)
        return bundles

    def _score_one(self, bundle):
        score = bundle._score
        if bundle.device_profile:
            score += 10
        if bundle.steps:
            score += min(len(bundle.steps) * 5, 20)
        if bundle.system_context and bundle.system_context.get("is_privileged"):
            score += 10
        bundle._score = min(score, 100)


class BundleFamily:
    def __init__(self, name, bundles=None):
        self.name = name
        self.bundles = bundles or []
        self.family_score = 0

    @property
    def size(self):
        return len(self.bundles)


class BundleCluster:
    def cluster(self, bundles):
        families = {}
        for b in bundles:
            comp_type = b.component_type
            if comp_type not in families:
                families[comp_type] = BundleFamily(comp_type)
            families[comp_type].bundles.append(b)

        result = []
        for name, family in families.items():
            family.family_score = sum(b._score for b in family.bundles) // max(len(family.bundles), 1)
            result.append(family)

        return result
