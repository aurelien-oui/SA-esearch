/* Page Query : affichage de la requête envoyée à Elasticsearch (debug=true).
 *
 * La commande montre la requête en warning (« esearch debug — requête envoyée
 * à Elasticsearch : POST <url> <corps JSON> ») : ce script la lit dans les
 * messages du job de la recherche principale et l'affiche, corps indenté.
 * Texte posé par textContent, jamais interprété comme du HTML.
 * Il vide aussi l'étiquette quand on repasse en Debug « Non » : sinon une
 * étiquette saisie puis masquée partirait avec debug=false (refusé).
 *
 * Langage (1.24.0) : à la SOUMISSION seulement, pose exec_lucene ou exec_esql
 * dans les tokens soumis, d'après le langage soumis ; les deux recherches en
 * dépendent. Changer de langage dans le formulaire ne relance donc rien avant
 * Submit (un <set> de <change> écrirait aussi les tokens soumis).
 *
 * Limite (1.25.0) : son menu est peuplé par une recherche. Soumise avant, la
 * page n'avait aucun token soumis `limit`, et la recherche l'attendait sans
 * fin (« en attente d'entrée »). Sa première valeur rejoint donc les tokens
 * soumis quand une soumission l'a précédée.
 *
 * Aucun profil (1.26.0) : le bandeau disait seulement « aucun profil ». Pour un
 * utilisateur sans la capability esearch_run, la cause — que | esprofiles
 * donne en clair — n'apparaissait nulle part (Index affichait « Impossible de
 * créer une recherche »). Le message de la commande est recopié dans le
 * bandeau, en texte. */
require([
  "splunkjs/mvc",
  "splunkjs/mvc/simplexml/ready!"
], function (mvc) {
  "use strict";
  var PREFIXE = "esearch debug — requête envoyée à Elasticsearch : ";
  var bloc = document.getElementById("esearch-requete");
  var ligne = document.getElementById("esearch-requete-ligne");
  var corps = document.getElementById("esearch-requete-corps");
  var recherches = [mvc.Components.get("esearch_recherche"),
                    mvc.Components.get("esearch_recherche_esql")];
  var jetons = mvc.Components.get("default");
  var soumis = mvc.Components.get("submitted");

  function masquer() {
    if (bloc) { bloc.style.display = "none"; }
  }

  function afficher(texte) {
    // « POST <url> <json> » : méthode et URL d'un côté, corps de l'autre.
    var m = /^(\S+) (\S+) ([\s\S]*)$/.exec(texte);
    var tete = m ? m[1] + " " + m[2] : texte;
    var json = m ? m[3] : "";
    try { json = JSON.stringify(JSON.parse(json), null, 2); } catch (e) { /* tel quel */ }
    ligne.textContent = tete;
    corps.textContent = json;
    bloc.style.display = "";
  }

  recherches.forEach(function (recherche) {
    if (!recherche) { return; }
    recherche.on("search:start", masquer);
    recherche.on("search:done", function (proprietes) {
      var messages = (proprietes && proprietes.content && proprietes.content.messages) || [];
      for (var i = 0; i < messages.length; i++) {
        var t = messages[i] && messages[i].text;
        if (t && t.indexOf(PREFIXE) === 0) { afficher(t.slice(PREFIXE.length)); return; }
      }
      masquer();
    });
  });

  var profils = mvc.Components.get("esearch_profils");
  var cause = document.getElementById("esearch-cause-profils");
  function causeProfils(proprietes) {
    if (!cause) { return; }
    var messages = (proprietes && proprietes.content && proprietes.content.messages) || [];
    var texte = "";
    for (var i = 0; i < messages.length; i++) {
      var t = messages[i] && messages[i].text;
      if (t && messages[i].type === "ERROR") { texte = t; break; }
    }
    if (texte.indexOf("esearch_run") >= 0) {
      texte += " — demandez à un administrateur le rôle esearch_user, ou la capability "
        + "esearch_run pour l'un de vos rôles.";
    }
    cause.textContent = texte;
    cause.style.display = texte ? "" : "none";
  }
  if (profils) {
    profils.on("search:done", causeProfils);
    profils.on("search:failed", causeProfils);
  }

  function executer(langage) {
    if (!soumis || !langage) { return; }
    masquer();
    if (langage === "esql") {
      soumis.unset("exec_lucene");
      soumis.set("exec_esql", "true");
    } else {
      soumis.unset("exec_esql");
      soumis.set("exec_lucene", "true");
    }
  }
  if (soumis) {
    soumis.on("change:langage", function (modele, valeur) { executer(valeur); });
    executer(soumis.get("langage"));     // page rechargée après une soumission
  }
  if (jetons && !jetons.get("vue_esql") && !jetons.get("vue_lucene")) {
    // Affichage initial des champs, d'après le langage du formulaire (URL comprise).
    jetons.set(jetons.get("form.langage") === "esql" ? "vue_esql" : "vue_lucene", "true");
  }
  if (jetons && soumis) {
    jetons.on("change:form.limit", function (modele, valeur) {
      if (valeur && soumis.get("langage") && !soumis.get("limit")) {
        soumis.set({"form.limit": valeur, "limit": valeur});
      }
    });
  }
  if (jetons) {
    jetons.on("change:form.debug", function (modele, valeur) {
      if (valeur !== "true") { jetons.set("form.debug_tag", ""); }
    });
  }
});
