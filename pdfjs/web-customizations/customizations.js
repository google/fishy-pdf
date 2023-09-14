/*
Copyright 2023 Google LLC

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

const DEBUG_LOGGING = false;

class Findings {
  constructor() {
    this.hash = null;
    this.errors = [];
    this.attachments = [];
    this.scripts = new Map(); // maps from sourcecode to places where the script was found.
    this.suspicious_annotations = [];
    this.links = [];
    this.other = [];
  }
}

class ScriptSourceInfo {
  constructor() {
    this.actions = new Map();
    this.showDetails = false;  // TODO: Make this a component.
  }

  add(action, sourceType, sourceDetail) {
    if (!this.actions.has(action)) {
      this.actions.set(action, new Map());
    }
    const amap = this.actions.get(action);

    if (!amap.has(sourceType)) {
      amap.set(sourceType, []);
    }
    const details = amap.get(sourceType);
    details.push(sourceDetail);
  }
}

class AttachmentInfo {
  constructor(source, filename, data) {
    this.source = source;
    this.filename = filename;
    this.data = data;
    this.hash = sha256(this.data);
  }

  async unwrapHash() {
    this.hash = await this.hash;
    return this.hash;
  }
}

class LinkInfo {
  constructor(source, url) {
    this.source = source;
    this.url = url;
  }
}

class WeirdnessInfo {
  constructor(source, weirdness, loggable) {
    this.source = source;
    this.weirdness = weirdness;
    this.loggable = Object.freeze(loggable);
  }
}



import { createApp } from 'vue'

const FindingGroup = {
  props: {
    name: String,
  },
  data() {
    return {
      collapsed: false,
    };
  },
  template: `
    <div class="group">
      <h2 @click="collapsed = !collapsed" class="clickable"><span class="collapser">{{collapsed ? '[+]' : '[−]'}}</span> {{name}}</h2>
      <div class="children" v-if="!collapsed">
        <slot></slot>
      </div>
    </div>
  `
}

const app = createApp({
  components: {
    FindingGroup
  },
  data() {
    return {
      findings: null
    };
  }
}).mount('#securityPanel')


let findings = null;


async function sha256(data) {
  const hash = await crypto.subtle.digest('sha-256', data);
  let hs = "";
  for (const h of new Uint8Array(hash)) {
    hs += h.toString(16).padStart("2", "0");
  }
  return hs;
}

async function populateDocHash(pdfdoc) {
  findings.hash = await sha256(await pdfdoc.getData());
}

async function populateDocAttachments(pdfdoc) {
  const attachments = await PDFViewerApplication.pdfDocument.getAttachments();
  if (attachments) {
    for (const a of Object.values(attachments)) {
      if (DEBUG_LOGGING) console.log("found attachment", attachments);
      const attInfo = new AttachmentInfo("Document", a.filename, a.content);
      await attInfo.unwrapHash();
      findings.attachments.push(attInfo);
    }
  } else {
    if (DEBUG_LOGGING) console.log('no (global) attachments - may still contain attachment annotations!');
  }
}

async function populateDocActions(pdfdoc) {
  addScriptActions("Document", "", await pdfdoc.getJSActions());
  const openAction = await pdfdoc.getOpenAction();  // "an {Array} containing the destination, or `null` when no open action is present"
  if (openAction) {
    if (DEBUG_LOGGING) console.log("OpenAction", openAction);
    const keys = Object.keys(openAction);
    if (keys.length == 0 || (keys.length == 1 && keys[0] == "dest")) {
      return;
    }
    const suspicion = new WeirdnessInfo("Document OpenAction", "Non-trivial OpenAction found - parsing not implemented!", openAction);
    findings.errors.push(suspicion);
  }

  const fieldObjects = await pdfdoc.getFieldObjects();
  if (fieldObjects) {
    Object.keys(fieldObjects).forEach((foName) => {
      fieldObjects[foName].forEach((foInstance, instanceIndex) => {
        addScriptActions("Field", `"${foName}" [${instanceIndex}]`, foInstance.actions)
      });
    });
  }
}

function addScriptActions(sourceType, sourceDetail, actions) {
  // getJSActions seems to return an object-of-arrays-of-string, e.g. {"PageOpen": ["javascriptcodestringgoeshere"]}
  if (!actions) {
    return;
  }
  const source = `${sourceType} ${sourceDetail}`;
  for (const actionType of Object.keys(actions)) {
    actions[actionType].forEach((codeSnippet) => {
      if (DEBUG_LOGGING) console.log(`${source} has action of type ${actionType}:`, codeSnippet);
      if (!findings.scripts.has(codeSnippet)) {
        findings.scripts.set(codeSnippet, new ScriptSourceInfo());
      }
      findings.scripts.get(codeSnippet).add(actionType, sourceType, sourceDetail);
    });
  }
}

async function processPage(i, pagePromise) {
  const page = await pagePromise;
  addScriptActions("Page", `${i}`, await page.getJSActions());

  const annotations = await page.getAnnotations("any");  // array-of-object, "annotationType", "subtype", ...
  const tasks = [];
  annotations.forEach((ann) => {
    if (DEBUG_LOGGING) console.log(`Page ${i} has annotation:`, ann);
    if (ann.actions) {  // Covers the interesting aspect of "Widget"
      addScriptActions("Annotation", `(${ann.subtype} on page ${i})`, ann.actions);
    }
    if (ann.unsafeUrl) {  // Covers the interesting aspect of "Link"
      if (DEBUG_LOGGING) console.log(`Extracted URL:`, ann.unsafeUrl);
      findings.links.push(new LinkInfo(`Page ${i}`, ann.unsafeUrl));
    }
    // case "FileAttachment":
    if (ann.subtype == "FileAttachment") {
      const attInfo = new AttachmentInfo(`Page ${i}`, ann.file.filename, ann.file.content);
      tasks.push(attInfo.unwrapHash());
      if (DEBUG_LOGGING) console.log(`attachment`, attInfo);
      findings.attachments.push(attInfo);
    }
    const KNOWN_ANNOTATIONS = [
      // Boring annotations.
      "Text", "Popup", "FreeText", "Line", "Square", "Circle", "PolyLine",
      "Polygon", "Caret", "Ink", "Highlight", "Underline", "Squiggly",
      "StrikeOut", "Stamp",
      // Interesting, but handled
      "Widget", "Link", "FileAttachment",
    ];
    if (!ann.subtype) {
      const suspicion = new WeirdnessInfo(`Page ${i}`, "annotation with missing subtype", ann);
      findings.suspicious_annotations.push(suspicion);
      if (DEBUG_LOGGING) console.log(`annotation without subtybe?`, suspicion);
    } else if (!KNOWN_ANNOTATIONS.includes(ann.subtype)) {
      const suspicion = new WeirdnessInfo(`Page ${i}`, `annotation with unusual subtype ${ann.subtype}`, ann);
      findings.suspicious_annotations.push(suspicion);
      if (DEBUG_LOGGING) console.log(`unusual annotation?`, suspicion);
    }
  });
  await Promise.all(tasks);
}

document.addEventListener("webviewerloaded", async () => {
  if (DEBUG_LOGGING) console.log("viewer loaded callback");

  window.PDFViewerApplicationOptions.setAll({
    "enableScripting": false, // parametrize?
    "disableTelemetry": true,
    "disablePreferences": true,
    "disableHistory": true,
    "defaultUrl": "",
    "pdfBugEnabled": true,  // needs to be activated with #pdfbug=all in the URL
    "pdfBug": "all", // I don't think this is ever used
    // "fontExtraProperties": true, // needed for pdfbug, enabled if the URL bar method is used
  });

  const pdfapp = window.PDFViewerApplication;
  await pdfapp.initializedPromise
  if (DEBUG_LOGGING) console.log("viewer initialized non-callback");
  pdfapp.eventBus.on("documentloaded", (e) => { if (DEBUG_LOGGING) console.log("doc loaded", e)});
  pdfapp.eventBus.on("documentinit", async (e) => { if (DEBUG_LOGGING) console.log("document init", e)});
  pdfapp.eventBus.on("metadataloaded", async (e) => {
    if (DEBUG_LOGGING) console.log("metadata loaded", e);
    const pdfdoc = pdfapp.pdfDocument;
    app.findings = null;
    findings = new Findings();

    if (pdfapp.documentInfo.IsAcroFormPresent) {
      findings.other.push(new WeirdnessInfo("documentInfo", "Document has AcroForm"));
    }
    if (pdfapp.documentInfo.IsXFAPresent) {
      findings.other.push(new WeirdnessInfo("documentInfo", "Document has XFA"));
    }
    if (pdfapp.documentInfo.IsSignaturesPresent) {
      findings.other.push(new WeirdnessInfo("documentInfo", "Document has signatures"));
    }

    const tasks = [];

    tasks.push(["Document: Hash", populateDocHash(pdfdoc)]);
    tasks.push(["Document: Attachments", populateDocAttachments(pdfdoc)]);
    tasks.push(["Document: Actions", populateDocActions(pdfdoc)]);
    for (let i = 1; i <= PDFViewerApplication.pdfDocument.numPages; i++) {
      tasks.push([`Page ${i}`, processPage(i, PDFViewerApplication.pdfDocument.getPage(i))]);
    }

    // Wait for completion
    for (const t of tasks) {
      try {
        await t[1];
      } catch (e) {
        console.log(e);
        findings.errors.push(new WeirdnessInfo(t[0], "Error while analyzing file: " + e, e))
      }
    }

    console.log("Analysis complete. Findings:", findings); // display
    app.findings = findings;
  });

});

document.addEventListener("DOMContentLoaded", () => {
  if (document.location.hash == "#pdfbug=all") {
    document.querySelector("#pdfbugButton").style = "display: none";
  }
});

