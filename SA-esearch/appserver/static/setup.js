/* Page de configuration esearch : CRUD des profils (configs/conf-esearch)
 * et de leurs secrets (storage/passwords), via le proxy splunkd de Splunk Web.
 * JS vanilla, sans dépendance externe (compatible CSP / AppInspect). */
(function () {
  "use strict";

  var APP = "SA-esearch";

  // Splunk Web sert ses URLs PRÉFIXÉES par la locale (/fr-FR/, /en-US/...).
  // Sans ce préfixe, splunkd répond par une REDIRECTION — et une redirection
  // HTTP transforme un POST en GET : le corps est perdu, la réponse vaut 200,
  // et l'écriture n'a jamais lieu. Les lectures, elles, fonctionnaient (un GET
  // redirigé reste un GET), d'où un réglage qui « revenait » à sa valeur
  // précédente sans le moindre message d'erreur.
  var LOCALE = (window.$C && window.$C.LOCALE)
    || (window.location.pathname.match(/^\/([A-Za-z]{2}[-_][A-Za-z]{2})\//) || [])[1]
    || "";
  var NS = (LOCALE ? "/" + LOCALE : "") + "/splunkd/__raw/servicesNS/nobody/" + APP;

  function csrfToken() {
    // Nom du cookie CSRF variable selon la version de Splunk Web.
    // On tente plusieurs variantes connues, du plus spécifique au plus général.
    var patterns = [
      /splunkweb_csrf_token_\d+=([^;]+)/,   // Splunk 6.5+ (avec port)
      /splunkweb_csrf_token=([^;]+)/,        // variante sans port
      /cval=([^;]+)/                          // très anciennes versions
    ];
    for (var i = 0; i < patterns.length; i++) {
      var m = document.cookie.match(patterns[i]);
      if (m) {
        return decodeURIComponent(m[1]);
      }
    }
    return "";
  }

  // Délai maximal d'un appel à splunkd (1.26.0) : sans lui, un splunkd qui ne
  // répond plus laissait la page attendre sans fin, sans rien afficher (1.16.2).
  var DELAI_API = 30000;

  // Liste des secrets : realm et username SEULEMENT (1.26.4). Sans le filtre
  // f=, splunkd renvoyait aussi chaque mot de passe en clair (clear_password)
  // au navigateur de l'administrateur, à chaque ouverture de la page, alors que
  // la page ne s'en sert jamais (revue de conception, E1). Aucune autre lecture
  // de la liste.
  var LISTE_SECRETS = "/storage/passwords?count=0&f=realm&f=username";

  function api(method, path, params) {
    var abandon = window.AbortController ? new AbortController() : null;
    var minuterie = abandon ? setTimeout(function () { abandon.abort(); }, DELAI_API) : null;
    var opts = {
      method: method,
      headers: {
        "X-Splunk-Form-Key": csrfToken(),
        "X-Requested-With": "XMLHttpRequest"
      },
      credentials: "same-origin",
      signal: abandon ? abandon.signal : undefined
    };
    // Garde-fou : une écriture ne doit JAMAIS suivre une redirection en silence
    // (POST -> GET = donnée perdue avec un 200 trompeur). On échoue bruyamment.
    if (method !== "GET") {
      opts.redirect = "error";
    }
    var url = NS + path + (path.indexOf("?") >= 0 ? "&" : "?") + "output_mode=json";
    if (params) {
      var body = Object.keys(params).map(function (k) {
        return encodeURIComponent(k) + "=" + encodeURIComponent(params[k]);
      }).join("&");
      opts.headers["Content-Type"] = "application/x-www-form-urlencoded";
      opts.body = body;
    }
    return fetch(url, opts).then(function (r) {
      return r.text().then(function (t) {
        var j = {};
        try { j = t ? JSON.parse(t) : {}; } catch (e) { j = { raw: t }; }
        if (!r.ok) {
          // 401 : la session Splunk Web a expiré. Le message brut était
          // « Unauthorized », sans dire quoi faire (1.16.2).
          var msg = r.status === 401
            ? "session expirée — reconnectez-vous (rechargez la page), puis recommencez"
            : (j.messages && j.messages[0] && j.messages[0].text) || r.status + " " + r.statusText;
          var err = new Error(msg);
          err.status = r.status;
          throw err;
        }
        return j;
      });
    }).catch(function (e) {
      // Erreur HTTP déjà traduite (statut joint) : telle quelle. Sinon, délai
      // dépassé — y compris pendant la lecture du corps — ou réseau.
      if (e && e.status) throw e;
      if (e && e.name === "AbortError") {
        throw new Error("splunkd ne répond pas (aucune réponse en " + DELAI_API / 1000
                        + " s) — la modification a pu être prise en compte : rechargez la "
                        + "page pour le vérifier");
      }
      throw new Error("splunkd injoignable (" + (e && e.message || e) + ") — vérifiez que "
                      + "Splunk tourne, puis rechargez la page");
    }).then(function (j) {
      if (minuterie) clearTimeout(minuterie);
      return j;
    }, function (e) {
      if (minuterie) clearTimeout(minuterie);
      throw e;
    });
  }

  // Bouton d'enregistrement occupé le temps de l'appel (1.26.0) : un second clic
  // ne relance rien, et l'attente se voit. `promesse` peut être absente (saisie
  // refusée avant tout appel).
  function occupe(bouton, promesse) {
    if (!bouton || !promesse || !promesse.then) return;
    var libelle = bouton.textContent;
    bouton.disabled = true;
    bouton.textContent = "Enregistrement en cours…";
    var fin = function () { bouton.disabled = false; bouton.textContent = libelle; };
    promesse.then(fin, fin);
  }

  function $(id) { return document.getElementById(id); }

  // splunkd NORMALISE les booléens en "1"/"0" à la lecture, alors que nos
  // <select> proposent "true"/"false". Affecter "1" à un select qui n'a pas
  // cette option le laisse VIDE — et l'enregistrement suivant écrivait alors
  // une valeur vide en conf (mode ad hoc désactivé, vérification TLS perdue).
  function boolStr(v) {
    return ["1", "true", "yes", "on", "t", "y"].indexOf(
      String(v).trim().toLowerCase()) >= 0 ? "true" : "false";
  }

  var BOOLEENS = ["allow_adhoc_host", "verify_certs", "detect_version",
                  "sanitize_metadata_fields", "esql_hide_keyword"];

  // Zones de message, chacune à côté des boutons qui la concernent. Jusqu'en
  // 1.13.0, une seule zone en HAUT de page : avec quelques dizaines de profils,
  // elle se trouvait ~2 600 px au-dessus du bouton « Enregistrer » du profil.
  // L'admin cliquait et ne voyait rien — ni l'erreur de validation, ni le succès.
  var ZONES = ["esearch-msg", "esearch-msg-settings", "esearch-msg-profils",
               "esearch-msg-form", "esearch-msg-ordre"];
  var MSG_FORM = "esearch-msg-form", MSG_PROFILS = "esearch-msg-profils",
      MSG_SETTINGS = "esearch-msg-settings", MSG_ORDRE = "esearch-msg-ordre";

  function flash(text, ok, zone) {
    var el = $(zone || "esearch-msg") || $("esearch-msg");
    if (!el) return;
    // un seul message à la fois : pas de message périmé laissé ailleurs
    ZONES.forEach(function (z) {
      var autre = $(z);
      if (autre && autre !== el) autre.style.display = "none";
    });
    el.textContent = text;
    el.className = "esearch-msg " + (ok ? "ok" : "err");
    el.style.display = "block";
    // ne fait défiler que si la zone est hors de vue
    if (el.scrollIntoView) el.scrollIntoView({ block: "nearest" });
    // le masquage différé ne doit pas effacer un message affiché depuis
    var gen = el.esearchGen = (el.esearchGen || 0) + 1;
    if (ok) setTimeout(function () { if (el.esearchGen === gen) el.style.display = "none"; }, 4000);
  }

  // ---- lecture des profils + secrets ----
  function loadProfiles() {
    Promise.all([
      api("GET", "/configs/conf-esearch?count=0"),
      api("GET", LISTE_SECRETS).catch(function () { return { entry: [] }; })
    ]).then(function (res) {
      var stanzas = res[0].entry || [];
      var secrets = {}, entrees = {};
      (res[1].entry || []).forEach(function (e) {
        if (e.content && e.content.realm && e.content.realm.indexOf("esearch:") === 0) {
          var p = e.content.realm.slice("esearch:".length);
          secrets[p] = true;
          (entrees[p] = entrees[p] || []).push(e.name);
        }
      });
      // Secrets dont le profil n'existe plus (supprimé hors de cette page :
      // esearch.conf édité, outil de déploiement). Le secret n'étant lié qu'au
      // NOM du profil, un profil recréé sous ce nom le réutiliserait en silence
      // — y compris vers un autre cluster.
      var profils = {};
      stanzas.forEach(function (s) {
        if (s.name.indexOf("profile:") === 0) profils[s.name.slice("profile:".length)] = true;
      });
      renderOrphelins(Object.keys(entrees).filter(function (p) { return !profils[p]; })
        .map(function (p) { return { profil: p, noms: entrees[p] }; }));
      var rows = stanzas.filter(function (s) { return s.name.indexOf("profile:") === 0; })
        .map(function (s) {
          var name = s.name.slice("profile:".length);
          var c = s.content || {};
          return { name: name, host: c.es_host || "", auth: c.auth_type || "none",
                   // splunkd renvoie "0"/"1" : passer par boolStr, sinon un profil
                   // dont la vérification TLS est DÉSACTIVÉE s'affiche « vérifié »
                   verify: c.verify_certs === undefined || boolStr(c.verify_certs) === "true",
                   secret: !!secrets[name], content: c };
        });
      renderProfiles(rows);
      var reglages = stanzas.filter(function (s) { return s.name === "settings"; })[0];
      PROFILS = rows;
      ORDRE = ordonne(rows.map(function (r) { return r.name; }),
                      reglages && reglages.content ? reglages.content.profile_order : "");
      ORDRE_ENREGISTRE = ORDRE.join(",");
      renderOrdre();
    }).catch(function (e) { flash("Lecture des profils impossible : " + e.message, false); });
  }

  function renderOrphelins(orphelins) {
    var box = $("esearch-orphelins");
    if (!box) return;
    if (!orphelins.length) { box.style.display = "none"; box.innerHTML = ""; return; }
    box.style.display = "block";
    box.innerHTML = "<b>Secrets orphelins</b> — leur profil n'existe plus. Un profil recréé "
      + "sous l'un de ces noms les réutiliserait sans qu'on les lui fournisse : "
      + orphelins.map(function (o) { return "<code>" + esc(o.profil) + "</code>"; }).join(", ")
      + ' <button id="esearch-purge-orphelins">Purger ces secrets</button>';
    $("esearch-purge-orphelins").onclick = function () {
      if (!window.confirm("Supprimer définitivement " + orphelins.length
                          + " secret(s) orphelin(s) ?")) return;
      Promise.all([].concat.apply([], orphelins.map(function (o) {
        return o.noms.map(function (n) {
          return api("DELETE", "/storage/passwords/" + encodeURIComponent(n))
                   .then(function () { return true; }).catch(function () { return false; });
        });
      }))).then(function (res) {
        var ko = res.filter(function (x) { return !x; }).length;
        flash((res.length - ko) + " secret(s) orphelin(s) supprimé(s)."
              + (ko ? " " + ko + " n'ont PAS pu l'être." : ""), !ko, MSG_PROFILS);
        loadProfiles();
      });
    };
  }

  // Supprime tous les secrets d'un profil (realm esearch:<profil>).
  function purgeSecrets(profil) {
    return api("GET", LISTE_SECRETS).then(function (r) {
      var noms = (r.entry || []).filter(function (e) {
        return e.content && e.content.realm === "esearch:" + profil;
      }).map(function (e) { return e.name; });
      return Promise.all(noms.map(function (n) {
        return api("DELETE", "/storage/passwords/" + encodeURIComponent(n));
      })).then(function () { return noms.length; });
    });
  }

  // Les profils et leur ordre de priorité forment UNE liste (1.21.0) : jusqu'ici
  // un tableau des profils, puis, plus bas, la liste de priorité, à part.
  function renderProfiles(rows) {
    var nb = $("t-nb");
    if (nb) nb.textContent = "(" + rows.length + ")";
  }

  function esc(s) {
    return String(s).replace(/[&<>"]/g, function (c) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c];
    });
  }

  // ---- accès par rôle (allowed_roles) ----
  // Même lecture que profile_allowed_roles (sa_esearch/config.py) : vide =
  // non configuré (ouvert), "*" = tous, sinon liste de rôles.
  function regleAcces(brut) {
    var v = String(brut || "").trim();
    if (!v) return null;
    if (v === "*") return "*";
    return v.split(",").map(function (r) { return r.trim().toLowerCase(); })
            .filter(Boolean);
  }

  // Depuis la 1.16.0, la règle vaut pour TOUS les profils : tous passent par le
  // proxy, qui la contrôle, y compris sans authentification.
  function libelleAcces(brut) {
    var regle = regleAcces(brut);
    if (regle === null) {
      return '<span class="esearch-alerte">⚠ non configuré (ouvert) — à choisir</span>';
    }
    if (regle === "*") return "tous (esearch_run)";
    if (regle.length === 1 && regle[0] === "admin") return "administrateurs";
    return esc(regle.join(", ")) + " + admin";
  }

  // Rôles proposés : tous, sauf admin (toujours admis : c'est le premier choix)
  // et les rôles internes de Splunk.
  var ROLES = null;
  function chargeRoles() {
    return api("GET", "/authorization/roles?count=0").then(function (r) {
      IMPORTS = {};
      (r.entry || []).forEach(function (e) {
        IMPORTS[e.name] = (e.content && e.content.imported_roles) || [];
      });
      ROLES = (r.entry || []).map(function (e) { return e.name; }).filter(function (n) {
        return n !== "admin" && n !== "sc_admin" && !/^splunk[-_]system/.test(n);
      }).sort();
    }).catch(function (e) {
      ROLES = [];
      flash("Lecture des rôles Splunk impossible : " + e.message, false, MSG_FORM);
    });
  }

  function choixAcces() {
    var coche = document.querySelector('input[name="f-acces"]:checked');
    return coche ? coche.value : null;
  }

  function afficheRoles(coches) {
    var box = $("f-roles");
    if (!box) return;
    var noms = (ROLES || []).slice();
    // Un rôle enregistré mais introuvable reste affiché, coché : le décocher
    // est un choix de l'admin, pas un effet de bord de la page.
    coches.forEach(function (r) { if (noms.indexOf(r) < 0) noms.push(r); });
    box.innerHTML = noms.map(function (n) {
      var absent = (ROLES || []).indexOf(n) < 0;
      return '<label class="esearch-choix"><input type="checkbox" name="f-role" value="'
        + esc(n) + '"' + (coches.indexOf(n) >= 0 ? " checked" : "") + "/>" + esc(n)
        + (absent ? ' <span class="esearch-alerte">(rôle introuvable)</span>' : "")
        + "</label>";
    }).join("") || "<em>Aucun rôle à proposer.</em>";
    box.style.display = (choixAcces() === "roles") ? "block" : "none";
  }

  function rolesCoches() {
    return [].map.call(document.querySelectorAll('input[name="f-role"]:checked'),
                       function (c) { return c.value; });
  }

  // Valeur à écrire, ou {erreur}. Le choix est OBLIGATOIRE pour tout profil,
  // y compris à l'édition d'un profil antérieur : c'est ce qui rend explicite
  // l'ouverture qui était implicite.
  function valeurAcces() {
    var choix = choixAcces();
    if (!choix) {
      return { erreur: "Choisissez qui peut utiliser ce profil (bloc « Qui peut "
                       + "utiliser ce profil ? »)." };
    }
    if (choix !== "roles") return { valeur: choix };
    var roles = rolesCoches();
    if (!roles.length) {
      return { erreur: "Cochez au moins un rôle, ou choisissez « Administrateurs "
                       + "seulement »." };
    }
    return { valeur: roles.sort().join(",") };
  }

  // ---- ordre de priorité des profils ([settings] profile_order) ----
  // Une recherche sans profile= prend le premier profil de cette liste que
  // l'utilisateur a le droit d'utiliser (règle appliquée par le proxy). Même
  // algorithme que profils_ordonnes (sa_esearch/config.py) : les profils
  // listés d'abord, dans l'ordre, puis les autres par ordre alphabétique.
  var PROFILS = [], ORDRE = [], ORDRE_ENREGISTRE = "", IMPORTS = {}, VERIF = {};

  function ordonne(noms, brut) {
    var vus = [];
    String(brut || "").split(",").forEach(function (n) {
      n = n.trim();
      if (noms.indexOf(n) >= 0 && vus.indexOf(n) < 0) vus.push(n);
    });
    return vus.concat(noms.filter(function (n) { return vus.indexOf(n) < 0; }).sort());
  }

  function profil(nom) {
    return PROFILS.filter(function (p) { return p.name === nom; })[0];
  }

  // Rôles effectifs : les rôles cochés et tous ceux qu'ils importent.
  function effectifs(directs) {
    var vus = {}, pile = directs.slice();
    while (pile.length) {
      var r = pile.pop();
      if (!vus[r]) { vus[r] = true; pile = pile.concat(IMPORTS[r] || []); }
    }
    return vus;
  }

  // Même règle que acces_profil (config.py).
  function autorise(p, eff) {
    var regle = regleAcces(p.content.allowed_roles);
    if (regle === null || regle === "*" || eff.admin) return true;
    return regle.some(function (r) { return eff[r]; });
  }

  // Rendu unique : le tableau des profils, dans l'ordre de priorité, avec le
  // rang et ses flèches, le filtre, et l'éditeur replacé sous sa ligne.
  function renderOrdre() {
    var tb = document.querySelector("#esearch-profiles tbody");
    if (!tb) return;
    // L'éditeur peut être DANS le tableau : on le range avant de vider le
    // tableau, sinon il est détaché du document avec lui et ses champs perdus
    // (vu au navigateur pendant le développement de 1.21.0).
    var ed = $("esearch-editeur"), parking = $("esearch-parking");
    if (ed && parking) parking.appendChild(ed);
    var filtre = (($("p-filtre") || {}).value || "").trim().toLowerCase();
    var barre = $("o-barre");
    if (barre) barre.style.display = (ORDRE.join(",") !== ORDRE_ENREGISTRE) ? "flex" : "none";
    marqueSale();
    if (!ORDRE.length) {
      tb.innerHTML = '<tr><td colspan="8">Aucun profil. « Nouveau profil » pour en créer un.</td></tr>';
      placeEditeur(tb); renderVerif(); return;
    }
    tb.innerHTML = "";
    var montres = 0;
    ORDRE.forEach(function (n, i) {
      var r = profil(n);
      if (!r) return;
      var texte = (n + " " + r.host + " " + (r.content.allowed_roles || "")).toLowerCase();
      if (filtre && texte.indexOf(filtre) < 0) return;
      montres++;
      var need = (r.auth !== "none");
      // Flèches désactivées pendant un filtrage : monter un profil « au-dessus »
      // d'un voisin masqué ne ferait pas ce que l'on voit.
      var fige = !!filtre;
      var tr = document.createElement("tr");
      tr.setAttribute("data-nom", n);
      tr.innerHTML =
        '<td class="esearch-fleches"><span class="esearch-rang">' + (i + 1) + "</span>"
        + '<button type="button" data-ordre="' + i + '" data-sens="-1" aria-label="Monter ' + esc(n) + '"'
        + ((i === 0 || fige) ? " disabled" : "") + ">↑</button>"
        + '<button type="button" data-ordre="' + i + '" data-sens="1" aria-label="Descendre ' + esc(n) + '"'
        + ((i === ORDRE.length - 1 || fige) ? " disabled" : "") + ">↓</button></td>"
        + '<td><span class="esearch-nom">' + esc(n) + "</span></td>"
        + "<td>" + esc(r.host) + "</td>"
        + "<td>" + esc(r.auth) + "</td>"
        + "<td>" + (r.verify ? "vérifié" : "désactivé") + "</td>"
        + "<td>" + (need ? (r.secret ? "✔ défini" : "⚠ manquant") : "—") + "</td>"
        + "<td>" + libelleAcces(r.content.allowed_roles) + "</td>"
        + '<td class="row-actions"></td>';
      var td = tr.querySelector(".row-actions");
      var edit = document.createElement("button");
      edit.type = "button";
      edit.textContent = (EDITION === n) ? "Fermer" : "Éditer";
      edit.onclick = function () {
        if (EDITION === n) { fermeEditeur(); } else { fillForm(r); }
      };
      var del = document.createElement("button");
      del.type = "button";
      del.textContent = "Supprimer";
      del.onclick = function () { removeProfile(r.name); };
      td.appendChild(edit); td.appendChild(del);
      tb.appendChild(tr);
    });
    if (!montres) {
      tb.innerHTML = '<tr><td colspan="8">Aucun profil ne correspond au filtre.</td></tr>';
    }
    placeEditeur(tb);
    renderVerif();
  }

  // ---- éditeur de profil, ouvert EN PLACE ----
  // EDITION : nom du profil édité, "" pour un nouveau profil, null si fermé.
  // L'éditeur est un seul bloc du DOM, déplacé (pas recréé) : les valeurs
  // saisies survivent à un re-rendu de la liste (déplacement d'un profil).
  var EDITION = null;

  function placeEditeur(tb) {
    var ed = $("esearch-editeur"), parking = $("esearch-parking");
    if (!ed || !parking) return;
    if (EDITION === null) { parking.appendChild(ed); return; }
    var ligne = document.createElement("tr");
    ligne.className = "esearch-edition";
    var cellule = document.createElement("td");
    cellule.colSpan = 8;
    ligne.appendChild(cellule);
    var apres = EDITION ? tb.querySelector('tr[data-nom="' + cssEsc(EDITION) + '"]') : null;
    if (apres) {
      apres.className = "esearch-edite";
      apres.parentNode.insertBefore(ligne, apres.nextSibling);
    } else {
      tb.insertBefore(ligne, tb.firstChild);    // nouveau profil, ou ligne filtrée
    }
    cellule.appendChild(ed);
  }

  function cssEsc(v) { return String(v).replace(/["\\]/g, "\\$&"); }

  function ouvreEditeur(nom) {
    EDITION = nom;
    if (onglet() !== "profils") montreOnglet("profils");
    renderOrdre();
    var ed = $("esearch-editeur");
    if (ed && ed.scrollIntoView) ed.scrollIntoView({ block: "nearest" });
  }

  function fermeEditeur() {
    if (SALE.form && !window.confirm("Abandonner les modifications non enregistrées de ce profil ?")) return false;
    resetForm();
    return true;
  }

  function deplace(i, sens) {
    var j = i + sens;
    if (j < 0 || j >= ORDRE.length) return;
    var x = ORDRE[i]; ORDRE[i] = ORDRE[j]; ORDRE[j] = x;
    renderOrdre();
    // La liste est reconstruite : sans cela, le focus clavier retombait sur la
    // page et l'utilisateur au clavier repartait du début de la liste (vu au
    // navigateur). Il suit le profil déplacé : même flèche, ou l'autre si
    // celle-ci est désormais inactive (profil arrivé en tête ou en fin).
    var choix = ['[data-sens="' + sens + '"]', '[data-sens="' + (-sens) + '"]'];
    for (var k = 0; k < choix.length; k++) {
      var b = document.querySelector('#esearch-profiles button[data-ordre="' + j + '"]' + choix[k]);
      if (b && !b.disabled) { b.focus(); break; }
    }
  }

  function renderVerif() {
    var box = $("esearch-verif-roles"), res = $("esearch-verif-res");
    if (!box || !res) return;
    var noms = ["admin"].concat(ROLES || []);
    box.innerHTML = noms.map(function (n) {
      return '<label class="esearch-choix"><input type="checkbox" name="v-role" value="' + esc(n)
        + '"' + (VERIF[n] ? " checked" : "") + "/>" + esc(n) + "</label>";
    }).join("");
    var eff = effectifs(Object.keys(VERIF).filter(function (n) { return VERIF[n]; }));
    var ok = ORDRE.filter(function (n) { var p = profil(n); return p && autorise(p, eff); });
    [].forEach.call(document.querySelectorAll("#esearch-profiles tr[data-nom]"), function (tr) {
      var defaut = ok.length && tr.getAttribute("data-nom") === ok[0] && VERIF_OUVERT;
      tr.classList.toggle("defaut-verif", !!defaut);
    });
    res.innerHTML = ok.length
      ? "Profil par défaut : <b><code>" + esc(ok[0]) + "</code></b> (n° " + (ORDRE.indexOf(ok[0]) + 1)
        + " de la liste)." + (ok.length > 1 ? " Aussi autorisés avec <code>profile=</code> : "
        + ok.slice(1, 6).map(esc).join(", ")
        + (ok.length > 6 ? " et " + (ok.length - 6) + " autre(s)" : "") + "." : "")
      : '<span class="esearch-alerte">Aucun profil autorisé avec ces rôles : la recherche '
        + "sans profile= est refusée.</span>";
  }

  // Stanza [settings] absente (404) : on la crée. Sur toute AUTRE erreur
  // (session expirée, splunkd muet, refus), on la rend telle quelle : la
  // création relancée attendait un second délai complet — 60 s avant le
  // moindre message quand splunkd ne répondait plus (vu en 1.26.0).
  function creeSettingsSiAbsent(body) {
    return function (e) {
      if (e.status !== 404) throw e;
      return api("POST", "/configs/conf-esearch", Object.assign({ name: "settings" }, body));
    };
  }

  function saveOrdre() {
    var body = { profile_order: ORDRE.join(",") };
    return api("POST", "/configs/conf-esearch/settings", body)
      .catch(creeSettingsSiAbsent(body))
      .then(function () {
        ORDRE_ENREGISTRE = body.profile_order;
        renderOrdre();
        flash("Ordre enregistré : " + ORDRE.join(" › ") + ".", true, MSG_ORDRE);
      })
      .catch(function (e) { flash("Échec de l'enregistrement de l'ordre : " + e.message, false, MSG_ORDRE); });
  }

  // ---- formulaire ----
  // Mode d'auth et identifiant du profil AU MOMENT où on l'a ouvert en édition :
  // sert à savoir si l'enregistrement rend le secret existant inutilisable.
  var edite = null;

  // Bornes du plafond par profil : les mêmes que max_limit des réglages globaux.
  var BORNES_LIMITE = [1, 10000000];

  function toggleAuthRows() {
    var t = $("f-authtype").value;
    $("f-username-row").style.display = (t === "basic") ? "block" : "none";
    $("f-secret-row").style.display = (t === "none") ? "none" : "block";
    $("f-roles").style.display = (choixAcces() === "roles") ? "block" : "none";
  }

  function fillForm(r) {
    if (EDITION !== null && EDITION !== r.name && SALE.form
        && !window.confirm("Abandonner les modifications non enregistrées du profil en cours ?")) return;
    var c = r.content || {};
    $("f-editing").value = r.name;
    $("f-name").value = r.name;
    $("f-name").readOnly = true;
    $("f-host").value = c.es_host || "";
    $("f-timefield").value = c.timefield || "";
    // même normalisation : un "0" venant de splunkd doit afficher « désactivée »
    // (sinon éditer un profil réactive silencieusement la vérification TLS)
    $("f-verify").value = (c.verify_certs === undefined || c.verify_certs === null)
      ? "true" : boolStr(c.verify_certs);
    $("f-ca").value = c.ca_file || "";
    $("f-pagination").value = c.pagination || "";
    $("f-clientcert").value = c.client_cert || "";
    $("f-clientkey").value = c.client_key || "";
    // "*" est la valeur par défaut : on laisse le champ vide dans ce cas
    $("f-indexpattern").value = (c.index_pattern === "*") ? "" : (c.index_pattern || "");
    $("f-maxlimit").value = c.max_limit || "";
    // Vide = réglage global ; boolStr("") vaudrait "false" et figerait le profil.
    $("f-esqlmode").value = c.esql_mode || "";
    $("f-esqlkeyword").value = (c.esql_hide_keyword === undefined || c.esql_hide_keyword === null
                                || String(c.esql_hide_keyword).trim() === "")
      ? "" : boolStr(c.esql_hide_keyword);
    $("f-authtype").value = c.auth_type || "none";
    $("f-username").value = c.username || "";
    $("f-secret").value = "";
    edite = { auth: c.auth_type || "none", username: c.username || "" };
    var regle = regleAcces(c.allowed_roles);
    var choix = (regle === null) ? null : (regle === "*") ? "*"
      : (regle.length === 1 && regle[0] === "admin") ? "admin" : "roles";
    [].forEach.call(document.querySelectorAll('input[name="f-acces"]'), function (b) {
      b.checked = (b.value === choix);
    });
    afficheRoles(choix === "roles" ? regle : []);
    toggleAuthRows();
    $("esearch-form-title").textContent = "Éditer le profil « " + r.name + " »";
    SALE.form = false;
    ouvreEditeur(r.name);
  }

  function resetForm() {
    edite = null;
    $("f-editing").value = "";
    $("esearch-form").reset();
    $("f-name").readOnly = false;
    $("esearch-form-title").textContent = "Nouveau profil";
    afficheRoles([]);
    toggleAuthRows();
    SALE.form = false;
    EDITION = null;
    renderOrdre();
  }

  function nouveauProfil() {
    if (EDITION !== null && SALE.form
        && !window.confirm("Abandonner les modifications non enregistrées du profil en cours ?")) return;
    resetForm();
    ouvreEditeur("");
    var nom = $("f-name");
    if (nom) nom.focus();
  }

  // ---- onglets ----
  function onglet() {
    var r = $("o-reglages");
    return (r && !r.hidden) ? "reglages" : "profils";
  }

  function montreOnglet(nom) {
    ["profils", "reglages"].forEach(function (n) {
      var panneau = $("o-" + n), bouton = $("t-" + n);
      if (panneau) panneau.hidden = (n !== nom);
      if (bouton) bouton.setAttribute("aria-selected", n === nom ? "true" : "false");
    });
    try { history.replaceState(null, "", nom === "reglages" ? "#reglages" : "#profils"); } catch (e) { /* sans effet */ }
  }

  // ---- modifications non enregistrées ----
  var SALE = { form: false, reglages: false };
  var VERIF_OUVERT = false;

  function marqueSale() {
    var ordre = ORDRE.join(",") !== ORDRE_ENREGISTRE;
    var p = $("t-profils-sale"), r = $("t-reglages-sale");
    if (p) p.textContent = (SALE.form || ordre) ? " ●" : "";
    if (r) r.textContent = SALE.reglages ? " ●" : "";
  }

  // Un saut de ligne dans une valeur est écrit par splunkd sous forme de
  // CONTINUATION (« \ » en fin de ligne). L'API REST — donc cette page — relit
  // alors une seule valeur multi-ligne, tandis que le moteur (configparser) lit
  // la ligne suivante comme une CLÉ À PART ENTIÈRE : un profil affiché
  // « auth_type = none » pouvait s'exécuter en « apikey ».
  //
  // Filet de sécurité seulement : un navigateur SUPPRIME déjà les sauts de
  // ligne affectés à un <input type="text"> (vérifié sur Splunk 10.4.1), donc
  // ce contrôle ne se déclenche pas depuis cette page telle qu'elle est
  // aujourd'hui. Il sert si un champ devient un <textarea>. La détection qui
  // compte est côté serveur, au chargement de la conf (sa_esearch/config.py),
  // parce que le vrai vecteur est une écriture REST ou une édition manuelle.
  // Deux formes à refuser, pas une : le saut de ligne, et l'antislash FINAL.
  // Le navigateur supprime déjà les sauts de ligne d'un <input type="text">,
  // si bien que le vecteur réellement atteignable depuis cette page est une
  // valeur terminée par « \ » (un chemin Windows « C:\certs\ », par exemple) :
  // splunkd l'écrit telle quelle et la relit comme une continuation de ligne.
  function valeursSuspectes(valeurs) {
    return Object.keys(valeurs).filter(function (k) {
      var v = String(valeurs[k]);
      return /[\r\n]/.test(v) || /\\$/.test(v.replace(/\s+$/, ""));
    });
  }

  // Bloc unique : il était dupliqué entre le formulaire de profil et celui des
  // réglages, avec le risque de n'en corriger qu'un.
  function refuseContinuation(valeurs, zone) {
    var mauvaises = valeursSuspectes(valeurs);
    if (!mauvaises.length) { return false; }
    flash("Valeur refusée (" + mauvaises.join(", ") + ") : un saut de ligne ou un "
          + "antislash final crée une continuation de ligne, et Splunk ne la lirait "
          + "pas comme le moteur.", false, zone);
    return true;
  }

  function saveProfile() {
    var name = $("f-name").value.trim();
    if (!/^[A-Za-z0-9_.-]+$/.test(name) || /^\.+$/.test(name)) {
      flash("Nom de profil invalide.", false, MSG_FORM); return;
    }
    var authType = $("f-authtype").value;
    var content = {
      es_host: $("f-host").value.trim(),
      verify_certs: $("f-verify").value,
      auth_type: authType
    };
    // Champs optionnels : on poste TOUJOURS la clé, vide comprise. Ne poster que
    // les champs non vides laissait l'ancienne valeur en conf lors d'une édition
    // — un ca_file ou un client_cert « retiré » restait actif (profil cassé, ou
    // confiance TLS qu'on croyait supprimée).
    var OPTIONNELS = { timefield: "f-timefield", ca_file: "f-ca",
                       pagination: "f-pagination", client_cert: "f-clientcert",
                       client_key: "f-clientkey", index_pattern: "f-indexpattern",
                       max_limit: "f-maxlimit", esql_hide_keyword: "f-esqlkeyword",
                       esql_mode: "f-esqlmode" };
    Object.keys(OPTIONNELS).forEach(function (k) {
      var el = $(OPTIONNELS[k]);
      if (el) content[k] = el.value.trim();
    });
    // username n'a de sens qu'en auth basic : on le vide sinon, pour ne pas
    // laisser traîner un identifiant obsolète après changement de mode d'auth.
    content.username = (authType === "basic") ? $("f-username").value.trim() : "";
    var acces = valeurAcces();
    if (acces.erreur) { flash(acces.erreur, false, MSG_FORM); return; }
    content.allowed_roles = acces.valeur;
    if (!content.es_host) { flash("L'hôte Elasticsearch est requis.", false, MSG_FORM); return; }
    // Un hôte sans schéma (« es:9200 ») s'enregistrait sans broncher et ne
    // échouait qu'à la première recherche, sur une MissingSchema opaque.
    if (!/^https?:\/\/[^\s]+$/i.test(content.es_host)) {
      flash("L'hôte doit être une URL complète, http:// ou https:// "
            + "(ex. https://es.example.com:9200).", false, MSG_FORM); return;
    }
    // Idem : auth basic sans identifiant produisait un profil impossible à
    // utiliser (le secret ne peut même pas être posé).
    if (authType === "basic" && !content.username) {
      flash("Un identifiant est requis pour l'authentification basic.", false, MSG_FORM); return;
    }
    // Plafond propre au profil : vide = celui des réglages globaux. Mêmes
    // séparateurs de milliers tolérés à la saisie que pour max_limit.
    if (content.max_limit) {
      var n = content.max_limit.replace(/[\s_  ]/g, "");
      if (!/^\d+$/.test(n) || +n < BORNES_LIMITE[0] || +n > BORNES_LIMITE[1]) {
        flash("Le plafond du profil doit être un entier entre " + BORNES_LIMITE[0]
              + " et " + BORNES_LIMITE[1] + " (ou vide).", false, MSG_FORM); return;
      }
      content.max_limit = n;
    }
    if (refuseContinuation(content, MSG_FORM)) { return; }

    var editing = $("f-editing").value;
    // Secret REQUIS quand l'enregistrement rendrait le secret existant
    // inutilisable : sans lui, le ménage ci-dessous supprime l'ancien secret
    // et le profil reste sans aucun. Jusqu'en 1.13.0, la page l'annonçait
    // en vert (« enregistré ») et le profil passait à « ⚠ manquant ».
    if (authType !== "none" && !$("f-secret").value) {
      var motif = !editing ? "à la création d'un profil authentifié"
        : (edite && edite.auth !== authType) ? "quand le type d'authentification change"
        : (authType === "basic" && edite && edite.username !== content.username)
          ? "quand l'identifiant change (le mot de passe enregistré appartient à « "
            + edite.username + " »)"
        : null;
      if (motif) {
        flash("Secret requis " + motif + " : sans lui, le profil serait inutilisable.",
              false, MSG_FORM);
        return;
      }
    }
    // Identifiants sur un transport en clair (1.26.4, E2 de la revue) : le
    // profil s'enregistre, mais le message le dit, et pas en vert.
    var enClair = (authType !== "none" && /^http:/i.test(content.es_host))
      ? " ATTENTION : hôte en http:// — les identifiants circuleront en clair sur "
        + "le réseau ; préférez https://." : "";
    var stanza = "profile:" + name;
    var write = editing
      ? api("POST", "/configs/conf-esearch/" + encodeURIComponent(stanza), content)
      : api("POST", "/configs/conf-esearch", Object.assign({ name: stanza }, content));

    var purges = 0;
    return write.then(function () {
      // CRÉATION : un secret déjà présent sous ce nom est un reste d'un ancien
      // profil (supprimé hors de cette page). Il serait réutilisé en silence ;
      // on le purge, après la création du profil (qui échoue si le nom existe).
      if (!editing) {
        return purgeSecrets(name).then(function (n) { purges = n; });
      }
    }).then(function () {
      var secret = $("f-secret").value;
      if (authType !== "none" && secret) {
        var user = (authType === "basic") ? content.username : "apikey";
        return saveSecret(name, user, secret);
      }
    // le ménage vient APRÈS l'écriture du nouveau secret, jamais avant
    }).then(function () {
      return nettoieSecretsObsoletes(name, authType, content.username);
    }).then(function (menage) {
      var msg = "Profil « " + name + " » enregistré."
        + (purges ? " " + purges + " ancien(s) secret(s) laissé(s) sous ce nom supprimé(s)." : "")
        + (menage.supprimes ? " " + menage.supprimes + " secret(s) devenu(s) inutile(s) supprimé(s)." : "")
        + enClair;
      if (menage.echecs) {
        flash(msg + " ATTENTION : " + menage.echecs + " secret(s) obsolète(s) n'ont PAS pu être "
              + "supprimés et restent actifs — retirez-les via storage/passwords.", false, MSG_FORM);
        resetForm(); loadProfiles(); return;
      }
      // Profil authentifié resté sans secret (il en manquait déjà un, et
      // aucun n'a été saisi) : enregistré, mais on ne l'annonce pas en vert.
      if (authType !== "none" && menage.restants === 0) {
        flash(msg + " ATTENTION : aucun secret n'est défini pour ce profil — ses "
              + "recherches échoueront tant qu'il n'est pas saisi.", false, MSG_FORM);
        resetForm(); loadProfiles(); return;
      }
      flash(msg, !enClair, MSG_FORM);
      resetForm();
      loadProfiles();
    }).catch(function (e) { flash("Échec : " + e.message, false, MSG_FORM); });
  }

  // Secret : mise à jour EN PLACE (POST sur l'entrée), création si elle n'existe
  // pas (404), et si un autre administrateur vient de la créer (409), mise à
  // jour : la dernière écriture gagne (décision de l'utilisateur, 1.26.0).
  // Jusqu'en 1.25.1 : suppression puis création. Un second enregistrement
  // simultané tombait entre les deux et échouait en 409 (10 à 20 % des tours,
  // mesuré en 1.16.2), et le profil restait un instant sans secret.
  function saveSecret(profile, user, password) {
    var realm = "esearch:" + profile;
    // splunkd nomme l'entrée « <realm>:<user>: » en ÉCHAPPANT les deux-points
    // internes au realm : esearch\:prod:apikey:. Sans cet échappement le DELETE
    // visait une entrée inexistante (échec avalé), puis le POST échouait en 409
    // « A password already exists » — le remplacement d'un secret depuis la page
    // était donc impossible, et la rotation devait passer par la ligne de commande.
    var id = encodeURIComponent(realm.replace(/:/g, "\\:"))
             + "%3A" + encodeURIComponent(user) + "%3A";
    function majEnPlace() {
      return api("POST", "/storage/passwords/" + id, { password: password });
    }
    return majEnPlace().catch(function (e) {
      if (e.status !== 404) throw e;
      return api("POST", "/storage/passwords", { name: user, realm: realm, password: password })
        .catch(function (e2) {
          if (e2.status !== 409) throw e2;
          return majEnPlace();
        });
    });
  }

  // Un profil ne doit conserver QUE le secret correspondant à son mode
  // d'authentification courant. Sans ce ménage, basculer apikey -> basic
  // laissait l'ancienne clé en place : invisible dans la page, mais REMISE EN
  // SERVICE si l'on repassait plus tard en apikey sans ressaisir de secret —
  // un identifiant qu'on croyait retiré (voire révoqué côté ES) redevenait
  // actif en silence. Vérifié en test.
  function nettoieSecretsObsoletes(profil, authType, username) {
    var attendu = (authType === "apikey") ? "apikey"
                : (authType === "basic") ? username : null;   // none -> aucun
    return api("GET", LISTE_SECRETS).then(function (r) {
      var duProfil = (r.entry || []).filter(function (e) {
        return e.content && e.content.realm === "esearch:" + profil;
      });
      var obsoletes = duProfil.filter(function (e) {
        return attendu === null || e.content.username !== attendu;
      });
      var restants = duProfil.length - obsoletes.length;
      return Promise.all(obsoletes.map(function (e) {
        // Ne JAMAIS avaler l'échec : une version antérieure annonçait
        // « N secret(s) supprimé(s) » quel que soit le résultat des DELETE.
        // Un secret qu'on croyait retiré survivait alors en silence, et
        // redevenait actif au retour en apikey — le défaut même que ce ménage
        // est censé empêcher.
        return api("DELETE", "/storage/passwords/" + encodeURIComponent(e.name))
                 .then(function () { return true; })
                 .catch(function () { return false; });
      })).then(function (res) {
        var ok = res.filter(Boolean).length;
        return { supprimes: ok, echecs: res.length - ok, restants: restants };
      });
    // restants inconnu (lecture impossible) : pas d'avertissement, faute de savoir
    }).catch(function () { return { supprimes: 0, echecs: 0, restants: null }; });
  }

  function removeProfile(name) {
    if (!window.confirm("Supprimer le profil « " + name + " » ?")) return;
    var stanza = "profile:" + name;
    api("DELETE", "/configs/conf-esearch/" + encodeURIComponent(stanza))
      .then(function () {
        // supprimer aussi les secrets liés (best-effort)
        return api("GET", LISTE_SECRETS).then(function (r) {
          var dels = (r.entry || []).filter(function (e) {
            return e.content && e.content.realm === "esearch:" + name;
          }).map(function (e) {
            return api("DELETE", "/storage/passwords/" + encodeURIComponent(e.name)).catch(function () {});
          });
          return Promise.all(dels);
        });
      })
      .then(function () { flash("Profil « " + name + " » supprimé.", true, MSG_PROFILS); loadProfiles(); })
      .catch(function (e) { flash("Suppression impossible : " + e.message, false, MSG_PROFILS); });
  }

  // Délégation au niveau document : survit aux re-render du panneau par le
  // framework de dashboard Splunk (les écouteurs directs seraient détachés).
  document.addEventListener("click", function (e) {
    var t = e.target;
    if (t && t.getAttribute && t.getAttribute("data-ordre") !== null) {
      e.preventDefault();
      deplace(+t.getAttribute("data-ordre"), +t.getAttribute("data-sens"));
      return;
    }
    if (!t || !t.id) return;
    if (t.id === "o-save") { e.preventDefault(); occupe(t, saveOrdre()); }
    else if (t.id === "f-save") { e.preventDefault(); occupe(t, saveProfile()); }
    else if (t.id === "f-reset") { e.preventDefault(); fermeEditeur(); }
  });
  document.addEventListener("change", function (e) {
    if (!e.target) return;
    if (e.target.name === "v-role") { VERIF[e.target.value] = e.target.checked; renderVerif(); return; }
    if (e.target.id === "f-authtype" || e.target.name === "f-acces") toggleAuthRows();
  });
  document.addEventListener("click", function (e) {
    var t = e.target && e.target.closest ? e.target.closest("button") : e.target;
    if (!t) return;
    if (t.id === "s-save") { e.preventDefault(); occupe(t, saveSettings()); }
    else if (t.getAttribute("data-onglet")) { e.preventDefault(); montreOnglet(t.getAttribute("data-onglet")); }
    else if (t.id === "p-nouveau") { e.preventDefault(); nouveauProfil(); }
    else if (t.id === "o-annule") {
      e.preventDefault();
      ORDRE = ordonne(PROFILS.map(function (p) { return p.name; }), ORDRE_ENREGISTRE);
      renderOrdre();
    } else if (t.id === "p-verif") {
      e.preventDefault();
      VERIF_OUVERT = !VERIF_OUVERT;
      $("esearch-verif").style.display = VERIF_OUVERT ? "block" : "none";
      renderVerif();
    }
  });
  // Saisie : marque la section modifiée ; filtre de la liste.
  document.addEventListener("input", function (e) {
    var t = e.target;
    if (!t) return;
    if (t.id === "p-filtre") { renderOrdre(); return; }
    if (t.closest && t.closest("#esearch-form")) { SALE.form = true; marqueSale(); }
    else if (t.closest && t.closest("#esearch-settings")) { SALE.reglages = true; marqueSale(); }
  });
  document.addEventListener("change", function (e) {
    var t = e.target;
    if (!t || !t.closest) return;
    if (t.closest("#esearch-form")) { SALE.form = true; marqueSale(); }
    else if (t.closest("#esearch-settings")) { SALE.reglages = true; marqueSale(); }
  });
  // Quitter la page avec des modifications non enregistrées : le navigateur demande.
  window.addEventListener("beforeunload", function (e) {
    if (SALE.form || SALE.reglages || ORDRE.join(",") !== ORDRE_ENREGISTRE) {
      e.preventDefault();
      e.returnValue = "";
    }
  });

  // ---- réglages globaux [settings] (configs/conf-esearch/settings) ----
  var SETTINGS = ["max_limit", "default_limit", "allow_adhoc_host", "verify_certs",
                  "pagination", "log_level", "detect_version", "max_timeout_read", "max_response_mb",
                  "query_max_bytes", "query_max_depth",
                  "sanitize_metadata_fields", "page_keep_alive", "lookup_fields_ignore",
                  "debug_search_scope", "debug_terms_max",
                  "esql_max_bytes", "esql_max_depth", "esql_hide_keyword",
                  "esql_lookup_values_max", "esql_async_wait", "esql_async_keep_alive",
                  "esql_async_max"];
  // Colonne ou motif de colonne de lookup : même forme que les champs acceptés
  // côté commande (sa_esearch/filtres.py), plus le joker `*`.
  var COLONNE = /^[A-Za-z0-9_@*][A-Za-z0-9_.@*-]*$/;
  // Durée Elasticsearch : même règle que conf_duree (sa_esearch/config.py),
  // entier strictement positif + unité. Le message d'erreur de pagination
  // expirée (1.13.0) renvoie à ce réglage : il doit être réglable ici.
  var DUREE_ES = /^([0-9]+)(nanos|micros|ms|s|m|h|d)$/;
  // Réglages entiers : bornes contrôlées AVANT envoi. Sans cela une saisie du
  // type « 50 000 » ou « abc » partait en conf et faisait échouer toutes les
  // recherches (le back-end retombe désormais sur le défaut, mais autant ne
  // jamais écrire une valeur invalide).
  var SETTINGS_INT = { max_limit: [1, 10000000], default_limit: [1, 10000000],
                       max_timeout_read: [1, 3600], max_response_mb: [1, 4096],
                       query_max_bytes: [1024, 2147483647], query_max_depth: [1, 100000],
                       debug_terms_max: [1, 100000],
                       esql_max_bytes: [1024, 1000000], esql_max_depth: [1, 400],
                       esql_lookup_values_max: [1, 65536], esql_async_max: [10, 86400] };

  function loadSettings() {
    api("GET", "/configs/conf-esearch/settings").then(function (d) {
      var c = (d.entry && d.entry[0] && d.entry[0].content) || {};
      SETTINGS.forEach(function (k) {
        var el = $("s-" + k);
        if (!el || c[k] === undefined || c[k] === null) return;
        el.value = (BOOLEENS.indexOf(k) >= 0) ? boolStr(c[k]) : String(c[k]);
      });
      SALE.reglages = false;
      marqueSale();
    }).catch(function () { /* pas encore de stanza settings : valeurs par défaut du form */ });
  }

  function saveSettings() {
    var body = {};
    var erreur = null;
    SETTINGS.forEach(function (k) {
      var el = $("s-" + k);
      if (!el) {
        // Un champ absent du DOM était auparavant ignoré EN SILENCE : le réglage
        // n'était alors jamais transmis et la page semblait « revenir » à la
        // valeur par défaut. On refuse désormais d'enregistrer à moitié.
        erreur = erreur || ("champ « " + k + " » introuvable dans la page — "
                            + "rechargez en vidant le cache (Ctrl+Maj+R).");
        return;
      }
      var v = String(el.value).trim();
      var bornes = SETTINGS_INT[k];
      if (bornes) {
        // on tolère les séparateurs de milliers à la saisie, pas en conf
        var n = v.replace(/[\s_  ]/g, "");
        if (!/^\d+$/.test(n) || +n < bornes[0] || +n > bornes[1]) {
          erreur = erreur || ("« " + k + " » doit être un entier entre "
                              + bornes[0] + " et " + bornes[1] + ".");
          return;
        }
        v = n;
      }
      if (k === "page_keep_alive" || k === "esql_async_wait" || k === "esql_async_keep_alive") {
        v = v.replace(/\s+/g, "");
        var d = DUREE_ES.exec(v);
        if (!d || +d[1] === 0) {
          erreur = erreur || ("« " + k + " » doit être une durée positive "
                              + "Elasticsearch : 30s, 2m, 5m, 1h…");
          return;
        }
      }
      if (k === "lookup_fields_ignore") {
        var cols = v.split(",").map(function (x) { return x.trim(); })
                    .filter(function (x) { return x; });
        var mauvaise = cols.filter(function (x) { return !COLONNE.test(x); })[0];
        if (mauvaise) {
          erreur = erreur || ("« lookup_fields_ignore » : colonne invalide « " + mauvaise
                              + " » (lettres, chiffres, _ . @ -, motifs *).");
          return;
        }
        v = cols.join(", ");
      }
      // garde-fou : un booléen ne doit JAMAIS partir vide en conf
      if (BOOLEENS.indexOf(k) >= 0) v = boolStr(v);
      body[k] = v;
    });
    if (erreur) { flash(erreur, false, MSG_SETTINGS); return; }
    if (refuseContinuation(body, MSG_SETTINGS)) { return; }
    if (+body.default_limit > +body.max_limit) {
      flash("La limite par défaut (" + body.default_limit + ") dépasse le plafond ("
            + body.max_limit + ").", false, MSG_SETTINGS);
      return;
    }
    // POST sur la stanza settings (créée si absente)
    return api("POST", "/configs/conf-esearch/settings", body)
      .catch(creeSettingsSiAbsent(body))
      // On relit la conf après écriture : ce qui s'affiche est donc ce qui est
      // réellement enregistré, et un écart se voit immédiatement.
      .then(function () {
        flash("Réglages enregistrés (plafond " + body.max_limit
              + ", limite par défaut " + body.default_limit + ").", true, MSG_SETTINGS);
        loadSettings();
      })
      .catch(function (e) { flash("Échec réglages : " + e.message, false, MSG_SETTINGS); });
  }

  var lastRoot = null;
  function boot() {
    var root = $("esearch-setup");
    // (re)initialise si le panneau vient d'apparaître ou d'être re-rendu
    if (root && root !== lastRoot) {
      lastRoot = root;
      montreOnglet(window.location.hash === "#reglages" ? "reglages" : "profils");
      toggleAuthRows();
      chargeRoles().then(function () { afficheRoles(rolesCoches()); renderVerif(); });
      loadProfiles();
      loadSettings();
    }
    setTimeout(boot, 500);
  }
  boot();
})();
