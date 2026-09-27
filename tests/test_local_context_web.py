"""Explicit host kubeconfig targeting in console forms, without cloud/environment selection."""
from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock

os.environ.setdefault("CLOUDSEED_HOME", tempfile.mkdtemp(prefix="cs-local-context-web-"))
from cloudseed import webui
from test_wave2_web import js_def

JS = (Path(webui.WEB_ROOT) / "app.js").read_text()


class LocalContextWebBackendTests(unittest.TestCase):
    def test_local_context_is_offered_without_a_selected_environment(self):
        with mock.patch.object(webui.paths.Env, "list_all", return_value=[]):
            actions = {a["name"]: a for a in webui.actions_catalog()}
            for name in ("cloudseed_kubectl", "cloudseed_helm"):
                self.assertEqual(actions[name]["schema"]["properties"]["local_context"]["type"], "boolean")
                self.assertNotIn("cloud", actions[name]["schema"].get("required", []))
                self.assertNotIn("env", actions[name]["schema"].get("required", []))

    def test_even_reads_require_explicit_host_target_confirmation(self):
        for name, args in (("cloudseed_kubectl", "get pods -A"), ("cloudseed_helm", "list -A")):
            with self.subTest(name=name):
                data = {"local_context": True, "args": args}
                with self.assertRaises(webui.NeedsConfirm) as raised:
                    webui.build_argv(name, data)
                self.assertIn("console server host", str(raised.exception))
                self.assertIn("Cloudseed Undo", str(raised.exception))
                self.assertIn("--local-context", raised.exception.argv)
                argv = webui.build_argv(name, {**data, "confirm": True})
                self.assertIn("--local-context", argv)
                self.assertNotIn("--env", argv)
                self.assertNotIn("aws", argv)

    def test_conflicting_environment_and_non_boolean_override_are_rejected(self):
        for name in ("cloudseed_kubectl", "cloudseed_helm"):
            for extra in ({"cloud": "aws"}, {"env": "dev"}, {"local_context": "true"}):
                with self.subTest(name=name, extra=extra), self.assertRaises(ValueError):
                    webui.build_argv(name, {"local_context": True, "args": "version", "confirm": True, **extra})

    def test_host_context_lock_never_resolves_the_selected_environment(self):
        with mock.patch.object(webui.paths.Env, "list_all", side_effect=AssertionError("environment lookup")), \
                mock.patch.object(webui.paths, "load_settings", side_effect=AssertionError("current environment lookup")):
            for argv in (["kubectl", "--local-context", "--", "get", "pods"],
                         ["-y", "--runtime", "local", "helm", "--local-context", "--", "list"],
                         ["helm", "--runtime=local", "--yes", "--local-context", "list"]):
                self.assertEqual(webui.env_key(argv), "*")
        with mock.patch.object(webui.paths.Env, "list_all", return_value=[]), \
                mock.patch.object(webui.paths, "load_settings", return_value={"current_env": "aws-managed"}):
            for argv in (["kubectl", "--", "get", "pods", "--local-context"],
                         ["kubectl", "get", "pods", "--local-context"],
                         ["helm", "--kube-context", "--local-context", "list"]):
                self.assertIsNone(webui.env_key(argv))


# The real actionForm/readForm/rule code runs against small DOM stand-ins. This exercises
# mode changes and the actual submitted arguments, without a browser or external cluster.
DOM = r"""
const walk = n => [n, ...(n.kids || []).filter(x => typeof x === 'object').flatMap(walk)];
const match = (n, selector) => selector.startsWith('[name=') ? n.name === selector.slice(7,-2) : n.tag === selector;
const $$ = (selector, root) => walk(root).filter(n => selector.split(',').some(s => match(n,s)));
const $ = (selector, root) => selector === '#modal-body' ? {contains:()=>false} : $$(selector,root)[0] || null;
const el = (tag, attrs={}, ...kids) => {
 const n = {tag,tagName:tag.toUpperCase(),checked:false,...attrs,attrs,kids:[],dataset:{},events:{},
  append(...xs){for(const x of xs.flat(Infinity)){if(x===null||x===undefined||x===false)continue; if(typeof x==='object')x.parent=this;this.kids.push(x);}},
  addEventListener(k,f){this.events[k]=f;},setAttribute(k,v){this[k]=v;},removeAttribute(k){delete this[k];},
  closest(selector){let n=this;while(n){if(selector==='[hidden]'&&n.hidden)return n;n=n.parent;}return null;}};
 n.append(...kids); return n;
};
const field=(name,prop,required,value)=>el('label',{},el('input',{name,type:prop.type==='boolean'?'checkbox':'text',checked:!!value,value:value===undefined?'':String(value)}));
const fieldLabel=(a,name)=>name, effectChip=()=>null, actionXq=()=>'', actionTitle=()=>'', explainBtn=()=>null;
const CSS={escape:s=>s};let selected={id:'aws-dev'};const currentEnv=()=>selected,envArgs=()=>({cloud:'aws',env:'dev'});
let submitted=[];const run=async(action,args,label)=>{submitted.push({action,args,label});return 'job';};
const toast=message=>{throw new Error(message);};
"""


@unittest.skipUnless(shutil.which("node"), "node is not installed")
class LocalContextWebFormTests(unittest.TestCase):
    def node(self, definitions, code, prelude=""):
        source = prelude + "\n" + "\n".join(js_def(JS, name) for name in definitions) + "\n" + code
        out = subprocess.run(["node"], input=source, capture_output=True, text=True, timeout=30)
        self.assertEqual(out.returncode, 0, out.stderr)
        return json.loads(out.stdout)

    def test_forms_omit_selected_environment_and_reset_confirmation_on_target_change(self):
        result = self.node(["const LOCAL_CONTEXT_NOTICE = ", "const FORM_UI = ", "const ruleHolds = ",
                            "function readField(", "function readForm(", "function actionForm("], r"""
(async()=>{
 const checks=[];
 for(const name of ['cloudseed_kubectl','cloudseed_helm']){
  const schema={properties:{args:{type:'string'},cloud:{type:'string'},env:{type:'string'},local_context:{type:'boolean'},confirm:{type:'boolean'}},required:['args']};
  selected={id:'aws-dev'};
  const form=actionForm({name,schema,destructive:true},{args:'version'},true);
  const mode=$('[name="local_context"]',form), confirm=$('[name="confirm"]',form);
  confirm.checked=true;mode.checked=true;form.events.change();
  const clearedOnLocal=!confirm.checked, cloudHidden=!!$('[name="cloud"]',form).closest('[hidden]');
  await form.onsubmit({preventDefault(){}});
  confirm.checked=true;mode.checked=false;form.events.change();
  const clearedOnEnvironment=!confirm.checked;
  await form.onsubmit({preventDefault(){}});
  selected=null;
  const external=actionForm({name,schema,destructive:true},{local_context:true,args:'version'},true);
  await external.onsubmit({preventDefault(){}});
  checks.push({clearedOnLocal,cloudHidden,clearedOnEnvironment,notice:walk(external).find(n=>n.role==='note').hidden});
 }
 console.log(JSON.stringify({checks,submitted}));
})().catch(e=>{console.error(e);process.exit(1);});
""", DOM)
        for check in result["checks"]:
            self.assertEqual(check, {"clearedOnLocal": True, "cloudHidden": True, "clearedOnEnvironment": True, "notice": False})
        for i, row in enumerate(result["submitted"]):
            if i % 3 == 1:
                self.assertEqual((row["args"]["cloud"], row["args"]["env"]), ("aws", "dev"))
            else:
                self.assertTrue(row["args"]["local_context"])
                self.assertNotIn("cloud", row["args"])
                self.assertNotIn("env", row["args"])
                self.assertFalse(row["args"]["confirm"])

    def test_job_labels_identify_host_context_without_claiming_selected_environment(self):
        result = self.node(["const jobLabel = "], """
console.log(JSON.stringify(['cloudseed_kubectl','cloudseed_helm'].map(action=>jobLabel(action,{local_context:true,cloud:'aws',env:'dev'}))));
""")
        self.assertEqual(result, ["kubectl · host kubeconfig", "helm · host kubeconfig"])

    def test_confirmation_names_host_target_and_only_sends_confirm_after_acknowledgment(self):
        result = self.node(["const LOCAL_CONTEXT_NOTICE = ", "function confirmRun("], r"""
let shown;const modalSnapshot=()=>null,closeModal=()=>{},modalExplain=()=>{},setTimeout=()=>{};
const modal=(title,body)=>{shown={title,body};};
(async()=>{
 const pending=confirmRun('cloudseed_kubectl',{local_context:true,args:'get pods'},'kubectl');
 const tick=walk(shown.body).find(n=>n.type==='checkbox'),button=walk(shown.body).find(n=>n.tag==='button'&&n.class==='btn rose');
 const before={disabled:button.disabled,sent:submitted.length};
 tick.checked=true;tick.onchange();await button.onclick();await pending;
 const text=n=>typeof n==='object'?(n.kids||[]).map(text).join(' '):String(n);
 console.log(JSON.stringify({before,enabled:!button.disabled,notice:text(shown.body),submitted}));
})().catch(e=>{console.error(e);process.exit(1);});
""", DOM)
        self.assertEqual(result["before"], {"disabled": True, "sent": 0})
        self.assertTrue(result["enabled"])
        self.assertIn("machine running this Cloudseed console", result["notice"])
        self.assertIn("not recorded in Cloudseed Undo", result["notice"])
        self.assertEqual(result["submitted"][0]["args"], {"local_context": True, "args": "get pods", "confirm": True})


if __name__ == "__main__":
    unittest.main()
